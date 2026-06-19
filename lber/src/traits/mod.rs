pub trait AsBER : Sized {
    fn encode_into(&self, &mut Vec<u8>);
    fn encode(&self) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        self.encode_into(&mut out);
        return out;
    }

    fn decode(&[u8]) -> Option<Self>;

    fn len(&self) -> u64;
}

pub trait BERPayload : Sized {
    fn encode_into(&self, &mut Vec<u8>);
    fn encode(&self) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        self.encode_into(&mut out);
        return out;
    }

    fn decode(&[u8]) -> Option<Self>;

    fn len(&self) -> u64;
}

pub trait BERTag : Sized {
    fn encode_into(&self, &mut Vec<u8>);
    fn encode(&self) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        self.encode_into(&mut out);
        return out;
    }

    fn decode(&[u8]) -> Option<Self>;
}
