# tlhelp32 [![][img_crates]][crates] [![][img_doc]][doc]

[img_crates]: https://img.shields.io/crates/v/tlhelp32.svg
[img_doc]: https://img.shields.io/badge/rust-documentation-blue.svg
[crates]: https://crates.io/crates/tlhelp32
[doc]: https://docs.rs/tlhelp32/

An abstraction over the windows tlhelp32 api.
It offers a generic Snapshot struct which acts as an iterator to easily iterate over the
returned entries.


## Example
```rust
fn main() {
    for entry in tlhelp32::Snapshot::new_process()? {
       println!("{:?}", entry);
    }
}
```
