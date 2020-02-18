use std::{io::Read, fmt, collections::{HashMap, hash_map::Entry}};

use petgraph::{graph::{DiGraph, NodeIndex}, dot::{Dot, Config}};
use pgp::{Signature, packet::{Packet, SignatureType, Subpacket, PublicKey, PublicSubkey}, composed::signed_key::{shared::PublicOrSecret, public::SignedPublicKey}, types::KeyTrait, packet::PacketParser, armor::Dearmor};

fn no_u(err: pgp::errors::Error) -> anyhow::Error {
    anyhow::anyhow!("{}", err)
}

#[derive(Debug, Clone)]
struct KeyId(pgp::types::KeyId);

impl From<pgp::types::KeyId> for KeyId {
    fn from(id: pgp::types::KeyId) -> Self {
        Self(id)
    }
}

impl AsRef<[u8]> for KeyId {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl std::hash::Hash for KeyId {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.as_ref().hash(state);
    }
}

impl std::cmp::Eq for KeyId { }
impl std::cmp::PartialEq for KeyId {
    fn eq(&self, other: &Self) -> bool {
        self.as_ref() == other.as_ref()
    }
}

enum Node {
    PublicKey(PublicKey),
    PublicSubkey(PublicSubkey),
    UnresolvedKey(KeyId),
}

impl fmt::Display for Node {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Node::PublicKey(key) => write!(f, "Public Key {}", hex::encode_upper(key.fingerprint()))?,
            Node::PublicSubkey(subkey) => write!(f, "Public Subkey {}", hex::encode_upper(subkey.fingerprint()))?,
            Node::UnresolvedKey(keyid) => write!(f, "Unresolved Key {}", hex::encode_upper(keyid))?,
        }
        Ok(())
    }
}

enum Edge {
    SubkeyBinding(Signature),
}

impl fmt::Display for Edge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Edge::SubkeyBinding(_) => write!(f, "Subkey Binding"),
        }
    }
}

fn main() -> anyhow::Result<()> {
    pretty_env_logger::init();

    let stdin = std::io::stdin();
    let mut input = Vec::new();
    stdin.lock().read_to_end(&mut input)?;
    let input = std::io::Cursor::new(input);

    let mut map = DiGraph::<Node, Edge>::new();

    let mut known_keys = HashMap::<KeyId, NodeIndex>::new();

    let mut last_key = None;
    let mut last_subkey = None;
    for packet in PacketParser::new(Dearmor::new(input)) {
        match packet.map_err(no_u)? {
            Packet::PublicKey(key) => {
                last_key = Some(key.clone());
                match known_keys.entry(key.key_id().into()) {
                    Entry::Occupied(entry) => {
                        map[*entry.get()] = Node::PublicKey(key);
                    }
                    Entry::Vacant(entry) => {
                        entry.insert(map.add_node(Node::PublicKey(key)));
                    }
                }
            }
            Packet::PublicSubkey(subkey) => {
                last_subkey = Some(subkey.clone());
                match known_keys.entry(subkey.key_id().into()) {
                    Entry::Occupied(entry) => {
                        map[*entry.get()] = Node::PublicSubkey(subkey);
                    }
                    Entry::Vacant(entry) => {
                        entry.insert(map.add_node(Node::PublicSubkey(subkey)));
                    }
                }
            }
            Packet::SecretKey(..) | Packet::SecretSubkey(..) => {
                panic!("Putting your secret key into this tool, what are you doing?");
            }
            Packet::Signature(sig) => {
                let mut issuer = || {
                    let keyid: KeyId = sig.issuer().unwrap().clone().into();
                    let issuer = known_keys.entry(keyid.clone()).or_insert_with(|| map.add_node(Node::UnresolvedKey(keyid)));
                    dbg!(*issuer)
                };
                match sig.typ() {
                    SignatureType::SubkeyBinding => {
                        let target = last_subkey.as_ref().unwrap();
                        let index = issuer();
                        map.add_edge(index, known_keys[&target.key_id().into()], Edge::SubkeyBinding(sig));
                    }
                    _ => {}
                }
            }
            Packet::Trust(..) => {}
            Packet::UserAttribute(..) => {}
            Packet::UserId(..) => {}
            _ => {}
        }
    }

    println!("{}", Dot::new(&map));

    for index in map.edge_indices() {
        match &map[index] {
            Edge::SubkeyBinding(sig) => {
                let (key, subkey) = map.edge_endpoints(index).unwrap();
                let key = match &map[key] { Node::PublicKey(key) => key, _ => panic!() };
                let subkey = match &map[subkey] { Node::PublicSubkey(subkey) => subkey, _ => panic!() };
                sig.verify_key_binding(key, subkey).unwrap();
            }
        }
    }
    Ok(())
}
