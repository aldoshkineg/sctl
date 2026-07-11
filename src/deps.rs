//! Dependency graph resolution for mount ordering and smart-cascade unmount.

use crate::config::Config;
use anyhow::{Result, bail};
use std::collections::BTreeSet;

/// Compute a mount order for `requested`, pulling in dependencies.
///
/// Returns names in dependency-first order (a dependency always appears before
/// the secret that depends on it), de-duplicated. Detects cycles.
pub fn mount_order(cfg: &Config, requested: &[String]) -> Result<Vec<String>> {
    // state: 0 = visiting, 1 = done
    let mut state: std::collections::HashMap<String, u8> = std::collections::HashMap::new();
    let mut order: Vec<String> = Vec::new();

    fn visit(
        cfg: &Config,
        name: &str,
        state: &mut std::collections::HashMap<String, u8>,
        order: &mut Vec<String>,
        chain: &mut Vec<String>,
    ) -> Result<()> {
        let secret = cfg.get(name)?;
        match state.get(name) {
            Some(1) => return Ok(()),
            Some(_) => {
                chain.push(name.to_string());
                bail!("dependency cycle: {}", chain.join(" -> "));
            }
            None => {}
        }
        state.insert(name.to_string(), 0);
        chain.push(name.to_string());
        for dep in &secret.depends {
            visit(cfg, dep, state, order, chain)?;
        }
        chain.pop();
        state.insert(name.to_string(), 1);
        order.push(name.to_string());
        Ok(())
    }

    let mut chain = Vec::new();
    for name in requested {
        visit(cfg, name, &mut state, &mut order, &mut chain)?;
    }
    Ok(order)
}

/// Outcome of planning an unmount.
#[derive(Debug, Default)]
pub struct UmountPlan {
    /// Secrets to unmount, in dependents-first order.
    pub order: Vec<String>,
    /// Requested secrets that are blocked because a mounted secret (not being
    /// unmounted) still depends on them: (blocked, blockers).
    pub blocked: Vec<(String, Vec<String>)>,
}

/// Plan a smart-cascade unmount.
///
/// - `requested`: explicitly requested names (must exist).
/// - `mounted`: set of currently mounted secret names.
///
/// Explicit requests whose mounted dependents are not also being unmounted are
/// reported as `blocked`. For everything else, dependencies that become unused
/// (no remaining mounted secret needs them) are cascaded in as well. The final
/// order is dependents-first (safe unmount order).
pub fn umount_plan(
    cfg: &Config,
    requested: &[String],
    mounted: &BTreeSet<String>,
) -> Result<UmountPlan> {
    let reqset: BTreeSet<&String> = requested.iter().collect();
    let mut plan = UmountPlan::default();
    let mut final_set: BTreeSet<String> = BTreeSet::new();

    for r in requested {
        cfg.get(r)?; // validate exists
        if !mounted.contains(r) {
            continue; // not mounted -> handled/reported by caller
        }
        // Mounted secrets that depend on r and are NOT themselves requested.
        let blockers: Vec<String> = mounted
            .iter()
            .filter(|m| !reqset.contains(*m))
            .filter(|m| {
                cfg.secrets
                    .get(*m)
                    .map(|s| s.depends.contains(r))
                    .unwrap_or(false)
            })
            .cloned()
            .collect();
        if blockers.is_empty() {
            final_set.insert(r.clone());
        } else {
            plan.blocked.push((r.clone(), blockers));
        }
    }

    // Cascade: pull in dependencies that become unused.
    loop {
        let mut added = false;
        let snapshot: Vec<String> = final_set.iter().cloned().collect();
        for u in snapshot {
            let deps = match cfg.secrets.get(&u) {
                Some(s) => s.depends.clone(),
                None => continue,
            };
            for d in deps {
                if !mounted.contains(&d) || final_set.contains(&d) {
                    continue;
                }
                // Any mounted secret (outside final_set) still needs d?
                let needed = mounted.iter().any(|m| {
                    !final_set.contains(m)
                        && m != &d
                        && cfg
                            .secrets
                            .get(m)
                            .map(|s| s.depends.contains(&d))
                            .unwrap_or(false)
                });
                if !needed {
                    final_set.insert(d);
                    added = true;
                }
            }
        }
        if !added {
            break;
        }
    }

    // Order dependents-first = reverse of dependency-first order, restricted to
    // the chosen set (must NOT pull in external deps like mount_order does).
    let names: Vec<String> = final_set.into_iter().collect();
    let mut ordered = order_subset(cfg, &names)?;
    ordered.reverse();
    plan.order = ordered;
    Ok(plan)
}

/// Topologically order only the secrets in `set`, following dependency edges
/// that stay within `set`. Unlike [`mount_order`], external dependencies are
/// never added.
fn order_subset(cfg: &Config, set: &[String]) -> Result<Vec<String>> {
    let in_set: std::collections::BTreeSet<&str> = set.iter().map(String::as_str).collect();
    let mut state: std::collections::HashMap<String, u8> = std::collections::HashMap::new();
    let mut order: Vec<String> = Vec::new();

    fn visit(
        cfg: &Config,
        name: &str,
        in_set: &std::collections::BTreeSet<&str>,
        state: &mut std::collections::HashMap<String, u8>,
        order: &mut Vec<String>,
        chain: &mut Vec<String>,
    ) -> Result<()> {
        match state.get(name) {
            Some(1) => return Ok(()),
            Some(_) => {
                chain.push(name.to_string());
                bail!("dependency cycle: {}", chain.join(" -> "));
            }
            None => {}
        }
        state.insert(name.to_string(), 0);
        chain.push(name.to_string());
        if let Some(secret) = cfg.secrets.get(name) {
            for dep in &secret.depends {
                if in_set.contains(dep.as_str()) {
                    visit(cfg, dep, in_set, state, order, chain)?;
                }
            }
        }
        chain.pop();
        state.insert(name.to_string(), 1);
        order.push(name.to_string());
        Ok(())
    }

    let mut chain = Vec::new();
    for name in set {
        visit(cfg, name, &in_set, &mut state, &mut order, &mut chain)?;
    }
    Ok(order)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, Secret};
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    fn sec(name: &str, depends: &[&str]) -> Secret {
        Secret {
            name: name.into(),
            rel_path: name.into(),
            idle: None,
            depends: depends.iter().map(|s| s.to_string()).collect(),
            gpg: false,
            gpg_preset: false,
            gpg_passphrase_file: None,
            auto_kill: vec![],
            kill_busy: false,
            kill_busy_after: None,
            pre_mount: vec![],
            post_mount: vec![],
            pre_unmount: vec![],
            post_unmount: vec![],
        }
    }

    fn cfg(secrets: Vec<Secret>) -> Config {
        let mut m = BTreeMap::new();
        for s in secrets {
            m.insert(s.name.clone(), s);
        }
        Config {
            home: PathBuf::from("/h"),
            state_dir: PathBuf::from("/c/state"),
            stray_dir: PathBuf::from("/c/stray"),
            enc_root: PathBuf::from("/e"),
            keyfile: PathBuf::from("/c/key"),
            default_idle: None,
            secrets: m,
        }
    }

    #[test]
    fn mount_pulls_deps_first() {
        let c = cfg(vec![
            sec("mail", &["gpg", "pass"]),
            sec("gpg", &[]),
            sec("pass", &["gpg"]),
        ]);
        let order = mount_order(&c, &["mail".into()]).unwrap();
        // gpg before pass before mail
        let pos = |n: &str| order.iter().position(|x| x == n).unwrap();
        assert!(pos("gpg") < pos("pass"));
        assert!(pos("pass") < pos("mail"));
        assert_eq!(order.len(), 3);
    }

    #[test]
    fn cycle_detected() {
        let c = cfg(vec![sec("a", &["b"]), sec("b", &["a"])]);
        assert!(mount_order(&c, &["a".into()]).is_err());
    }

    #[test]
    fn cascade_unmounts_unused_deps() {
        let c = cfg(vec![
            sec("mail", &["gpg", "pass"]),
            sec("gpg", &[]),
            sec("pass", &[]),
        ]);
        let mounted: BTreeSet<String> = ["mail", "gpg", "pass"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let plan = umount_plan(&c, &["mail".into()], &mounted).unwrap();
        // mail must come first, gpg+pass cascaded after
        assert_eq!(plan.order.first().unwrap(), "mail");
        assert_eq!(plan.order.len(), 3);
        assert!(plan.blocked.is_empty());
    }

    #[test]
    fn cascade_keeps_shared_dep() {
        // two consumers of gpg; unmount only mail -> gpg kept (chat needs it)
        let c = cfg(vec![
            sec("mail", &["gpg"]),
            sec("chat", &["gpg"]),
            sec("gpg", &[]),
        ]);
        let mounted: BTreeSet<String> = ["mail", "chat", "gpg"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let plan = umount_plan(&c, &["mail".into()], &mounted).unwrap();
        assert_eq!(plan.order, vec!["mail".to_string()]);
    }

    #[test]
    fn blocks_dependency_of_mounted() {
        let c = cfg(vec![sec("mail", &["gpg"]), sec("gpg", &[])]);
        let mounted: BTreeSet<String> = ["mail", "gpg"].iter().map(|s| s.to_string()).collect();
        let plan = umount_plan(&c, &["gpg".into()], &mounted).unwrap();
        assert!(plan.order.is_empty());
        assert_eq!(plan.blocked.len(), 1);
        assert_eq!(plan.blocked[0].0, "gpg");
        assert_eq!(plan.blocked[0].1, vec!["mail".to_string()]);
    }
}
