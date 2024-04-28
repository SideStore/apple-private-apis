use std::{io::Cursor, path::Path};

use paris_log::{debug, error};
use parking_lot::Mutex;
use plist::Value;

static DUMMY_BUNDLE_ID_NUM: Mutex<Counter> = Mutex::new(Counter(1));

struct Counter(i8);

impl Counter {
    pub fn val(&self) -> i8 {
        self.0
    }

    pub fn increase(&mut self) {
        self.0 += 1;
    }

    pub fn reset(&mut self) {
        self.0 = 1;
    }
}

fn add_bundle_id(bundle_id: &str, path: &Path) {
    let plist = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            error!("[<d>{}</d>] <red>{e:?}</>", path.display());
            return;
        }
    };
    let mut plist = match Value::from_reader(Cursor::new(plist)) {
        Ok(p) => p,
        Err(e) => {
            error!("[<d>{}</d>] <red>{}</>", path.display(), e);
            return;
        }
    };
    let plist = match plist.as_dictionary_mut() {
        Some(p) => p,
        None => {
            error!("[<d>{}</d>] <red>Not a dictionary</>", path.display());
            return;
        }
    };

    const BUNDLE_ID_PROPERTY: &str = "CFBundleIdentifier";
    if plist.get(BUNDLE_ID_PROPERTY).is_none() {
        let mut dummy_bundle_id_num_counter = DUMMY_BUNDLE_ID_NUM.lock();
        let dummy_bundle_id = format!("{bundle_id}.{}", dummy_bundle_id_num_counter.val());
        debug!(
            "[<d>{}</d>] <green>Info.plist does not have a bundle ID, giving `{dummy_bundle_id}` to it</>",
            path.display()
        );
        dummy_bundle_id_num_counter.increase();
        drop(dummy_bundle_id_num_counter);
        plist.insert(BUNDLE_ID_PROPERTY.to_owned(), plist::Value::String(dummy_bundle_id));

        let mut bytes = vec![];
        plist::to_writer_xml(&mut bytes, plist).unwrap();
        match std::fs::write(path, bytes) {
            Ok(_) => {}
            Err(e) => error!("[<d>{}</d>] <red>{e:?}</>", path.display()),
        };
    } else {
        debug!(
            "[<d>{}</d>] <yellow>Info.plist has a bundle ID, moving on</>",
            path.display(),
        )
    }
}

/// Goes through a .app and looks for Info.plist files. For every Info.plist that doesn't have a bundle ID, it adds a dummy bundle ID.
/// ### Arguments
/// - `app_path`: Path to the .app
/// - `bundle_id`: The dummy bundle ID. **This will have a number starting at 1 added to the end of the bundle ID to ensure they are unique.**
/// For example, if `bundle_id` is `com.SideStore`, the dummy bundle IDs that will be put into Info.plist files would be `com.SideStore.1`, `com.SideStore.2`, etc
pub fn add_dummy_bundle_ids(app_path: impl AsRef<Path>, bundle_id: &str) {
    DUMMY_BUNDLE_ID_NUM.lock().reset(); // ensure we start at 1

    ignore::WalkBuilder::new(app_path)
        .standard_filters(false)
        .threads(8)
        .build_parallel()
        .run(|| {
            Box::new(|result: Result<ignore::DirEntry, ignore::Error>| {
                match result {
                    Ok(entry) => {
                        let path = entry.path();
                        if path.file_name().map(|s| s.to_str()) == Some(Some("Info.plist")) {
                            add_bundle_id(bundle_id, path);
                        }
                    }
                    Err(e) => error!("<red>{e:?}</>"),
                };
                ignore::WalkState::Continue
            })
        });
}

#[cfg(test)]
mod tests {
    #[test]
    fn add_dummy_bundle_ids() {
        crate::tests::logger();

        super::add_dummy_bundle_ids("src/test.app", "com.wesbryie.test");
    }
}
