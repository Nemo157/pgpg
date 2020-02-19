use std::{
    collections::hash_map::Entry,
    convert::{TryFrom, TryInto},
    fmt,
    io::Read,
    iter::FromIterator,
};

use anyhow::anyhow;
use fxhash::{FxHashMap, FxHashSet};
use log::info;
use petgraph::{
    dot::Dot,
    graph::{DiGraph, NodeIndex},
    visit::EdgeRef,
    Direction,
};
use pgp::{
    armor::Dearmor,
    packet::{Packet, PacketParser, PublicKey, PublicSubkey, SignatureType, UserId},
    types::{KeyTrait, Tag},
    Signature,
};

fn no_u(err: pgp::errors::Error) -> anyhow::Error {
    anyhow!("{}", err)
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

impl std::cmp::Eq for KeyId {}
impl std::cmp::PartialEq for KeyId {
    fn eq(&self, other: &Self) -> bool {
        self.as_ref() == other.as_ref()
    }
}

#[derive(Debug, Copy, Clone)]
enum CertificationLevel {
    Generic,
    Persona,
    Casual,
    Positive,
}

impl TryFrom<SignatureType> for CertificationLevel {
    type Error = anyhow::Error;

    fn try_from(ty: SignatureType) -> Result<Self, Self::Error> {
        Ok(match ty {
            SignatureType::CertGeneric => CertificationLevel::Generic,
            SignatureType::CertPersona => CertificationLevel::Persona,
            SignatureType::CertCasual => CertificationLevel::Casual,
            SignatureType::CertPositive => CertificationLevel::Positive,
            _ => return Err(anyhow!("{:?} isn't a certification signature type", ty)),
        })
    }
}

enum Node {
    PublicKey(PublicKey),
    PublicSubkey(PublicSubkey),
    UserId(UserId),
    CertifiedId,
    UnresolvedKey(KeyId),
}

impl fmt::Display for Node {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Node::PublicKey(key) => {
                write!(f, "Public Key {}", hex::encode_upper(key.fingerprint()))?
            }
            Node::PublicSubkey(subkey) => write!(
                f,
                "Public Subkey {}",
                hex::encode_upper(subkey.fingerprint())
            )?,
            Node::UserId(user_id) => write!(f, "User Id {}", user_id.id())?,
            Node::CertifiedId => write!(f, "Certified Id")?,
            Node::UnresolvedKey(keyid) => write!(f, "Unresolved Key {}", hex::encode_upper(keyid))?,
        }
        Ok(())
    }
}

enum Edge {
    KeyBinding(Signature),
    SubkeyBinding(Signature),
    Certification(Signature, CertificationLevel),
    CertifiedUserId,
    CertifiedPublicKey,
}

impl fmt::Display for Edge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Edge::KeyBinding(_) => write!(f, "Key Binding"),
            Edge::SubkeyBinding(_) => write!(f, "Subkey Binding"),
            Edge::Certification(_, level) => write!(f, "{:?} Certification", level),
            Edge::CertifiedUserId => write!(f, "Certified User Id"),
            Edge::CertifiedPublicKey => write!(f, "Certified Public Key"),
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

    let mut known_keys = FxHashMap::<KeyId, NodeIndex>::default();
    let mut known_user_ids = FxHashMap::<String, NodeIndex>::default();

    let mut last_key = None;
    let mut last_subkey = None;
    let mut last_user_id = None;

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
            Packet::UserId(user_id) => {
                last_user_id = Some(user_id.clone());
                match known_user_ids.entry(user_id.id().to_owned()) {
                    Entry::Occupied(entry) => {
                        map[*entry.get()] = Node::UserId(user_id);
                    }
                    Entry::Vacant(entry) => {
                        entry.insert(map.add_node(Node::UserId(user_id)));
                    }
                }
            }
            Packet::Signature(sig) => {
                let issuer = sig.issuer().map(|issuer| {
                    let keyid: KeyId = issuer.clone().into();
                    *known_keys
                        .entry(keyid.clone())
                        .or_insert_with(|| map.add_node(Node::UnresolvedKey(keyid)))
                });
                match sig.typ() {
                    SignatureType::KeyBinding => {
                        let key = last_key.as_ref().unwrap();
                        let issuer = issuer.unwrap();
                        map.add_edge(
                            issuer,
                            known_keys[&key.key_id().into()],
                            Edge::KeyBinding(sig),
                        );
                    }
                    SignatureType::SubkeyBinding => {
                        let subkey = last_subkey.as_ref().unwrap();
                        let issuer = issuer.unwrap();
                        map.add_edge(
                            issuer,
                            known_keys[&subkey.key_id().into()],
                            Edge::SubkeyBinding(sig),
                        );
                    }
                    ty @ SignatureType::CertGeneric
                    | ty @ SignatureType::CertPersona
                    | ty @ SignatureType::CertCasual
                    | ty @ SignatureType::CertPositive => {
                        let user_id = last_user_id.as_ref().unwrap();
                        let user_id = known_user_ids[user_id.id()];
                        let key = last_key.as_ref().unwrap();
                        let key = known_keys[&key.key_id().into()];
                        let user_id_nodes = FxHashSet::from_iter(
                            map.edges_directed(user_id, Direction::Incoming)
                                .map(|e| e.source())
                                .filter(|id| matches!(map[*id], Node::CertifiedId)),
                        );
                        let key_nodes = FxHashSet::from_iter(
                            map.edges_directed(key, Direction::Incoming)
                                .map(|e| e.source())
                                .filter(|id| matches!(map[*id], Node::CertifiedId)),
                        );
                        let certified_id = user_id_nodes
                            .intersection(&key_nodes)
                            .next()
                            .copied()
                            .unwrap_or_else(|| {
                                let certified_id = map.add_node(Node::CertifiedId);
                                map.add_edge(certified_id, user_id, Edge::CertifiedUserId);
                                map.add_edge(certified_id, key, Edge::CertifiedPublicKey);
                                certified_id
                            });
                        let issuer = issuer.unwrap();
                        map.add_edge(
                            issuer,
                            certified_id,
                            Edge::Certification(sig, ty.try_into().unwrap()),
                        );
                    }
                    _ => {
                        info!("Skipping signature {:?}", sig);
                    }
                }
            }
            Packet::Trust(..) => {}
            Packet::UserAttribute(..) => {}
            packet => {
                info!("Skipping packet {:?}", packet);
            }
        }
    }

    println!("{}", Dot::new(&map));

    for index in map.edge_indices() {
        match &map[index] {
            Edge::KeyBinding(sig) => {
                let (subkey, key) = map.edge_endpoints(index).unwrap();
                let key = match &map[key] {
                    Node::PublicKey(key) => key,
                    _ => panic!(),
                };
                let subkey = match &map[subkey] {
                    Node::PublicSubkey(subkey) => subkey,
                    _ => panic!(),
                };
                sig.verify_key_binding(subkey, key).map_err(no_u)?;
            }
            Edge::SubkeyBinding(sig) => {
                let (key, subkey) = map.edge_endpoints(index).unwrap();
                let key = match &map[key] {
                    Node::PublicKey(key) => key,
                    _ => panic!(),
                };
                let subkey = match &map[subkey] {
                    Node::PublicSubkey(subkey) => subkey,
                    _ => panic!(),
                };
                sig.verify_key_binding(key, subkey).map_err(no_u)?;
            }
            Edge::Certification(sig, _) => {
                let (signing_key, certified_id) = map.edge_endpoints(index).unwrap();
                let signing_key = match &map[signing_key] {
                    Node::PublicKey(key) => key,
                    _ => panic!(),
                };
                let signed_key = map
                    .edges(certified_id)
                    .find(|e| {
                        if let Edge::CertifiedPublicKey = e.weight() {
                            true
                        } else {
                            false
                        }
                    })
                    .unwrap();
                let signed_key = match &map[signed_key.target()] {
                    Node::PublicKey(key) => key,
                    _ => panic!(),
                };
                let user_id = map
                    .edges(certified_id)
                    .find(|e| {
                        if let Edge::CertifiedUserId = e.weight() {
                            true
                        } else {
                            false
                        }
                    })
                    .unwrap();
                let user_id = match &map[user_id.target()] {
                    Node::UserId(user_id) => user_id,
                    _ => panic!(),
                };
                sig.verify_certificate(signing_key, &signed_key, Tag::UserId, user_id)
                    .map_err(no_u)?;
            }
            Edge::CertifiedUserId => {}
            Edge::CertifiedPublicKey => {}
        }
    }

    Ok(())
}
