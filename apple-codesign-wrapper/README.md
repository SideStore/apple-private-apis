# `apple-codesign-wrapper`

A wrapper for the `apple-codesign` crate to make it as easy to use as possible. This crate also does some additional things:

-   Scans the given .app for Info.plist files without a bundle ID and adds a dummy bundle ID since apple-codesign will fail if any Info.plist doesn't have a bundle ID.
-   In the future, it might do other things such as removing app extensions, modifying bundle IDs, etc
