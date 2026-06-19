use common::{TagClass, TagStructure};
use traits::{BERPayload, BERTag};

use structure::StructureTag;

use parse::{parse_length, parse_type_header};

use write::{write_length, write_type};

pub struct SpecificTag<T> {
    class: TagClass,
    id: u64,
    structure: TagStructure,
    inner: T,
}

impl<T: BERPayload> SpecificTag<T> {
    pub fn wrap(class: TagClass, id: u64, structure: TagStructure, inner: T) -> Self {
        SpecificTag {
            class: class,
            id: id,
            structure: structure,
            inner: inner,
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
                let b = j
                    .pop()
                    .expect("failed to get b")
                    .parse::<u32>()
                    .expect("failed to parse b");
                let a = j
                    .pop()
                    .expect("failed to get a")
                    .parse::<u32>()
                    .expect("failed to parse a");

                None
            } else {
                None
            }
        } else {
            None
        }
    }
}
