use traits::{BERPayload, BERTag};
use common::{TagStructure, TagClass};

use structure::StructureTag;

use parse::{parse_type_header, parse_length};

use write::{write_type, write_length};

pub struct SpecificTag<T> {
    class: TagClass,
    id: u64,
    structure: TagStructure,
    inner: T,
}

impl<T: BERPayload> SpecificTag<T> {
    pub fn wrap(class: TagClass,
                id: u64,
                structure: TagStructure,
                inner: T) -> Self {
        SpecificTag {
            class: class,
            id: id,
            structure: structure,
            inner: inner
        }
    }
}

struct Something {
    a: u32,
    b: u32,
}

impl Something {
    fn fill(tag: StructureTag) -> Option<Something> {
        if let Some(i) = tag
            .match_class(TagClass::Application)
            .and_then(|x| x.match_id(42u64))
        {
            if let Some(mut j) = i.expect_constructed() {
                let b = j.pop().unwrap();
                let a = j.pop().unwrap();

                None

            } else {
                None
            }
        } else {
            None
        }
    }
}
