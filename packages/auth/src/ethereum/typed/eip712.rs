use saa_common::AuthError;
use std::{collections::BTreeSet, str::FromStr};
pub use saa_common::types::exts::Eip712Types;

use serde_json::Value;
use serde::{Deserialize, Serialize};
use primitive_types::{H160, U256};
use saa_crypto::hashes::keccak256;


type Int = U256;
type Uint = U256;
type Word = [u8; 32];



#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub(crate) enum Token {
	/// Address.
	///
	/// solidity name: address
	/// Encoded to left padded [0u8; 32].
	Address(H160),
	/// Vector of bytes with known size.
	///
	/// solidity name eg.: bytes8, bytes32, bytes64, bytes1024
	/// Encoded to right padded [0u8; ((N + 31) / 32) * 32].
	FixedBytes(Vec<u8>),
	/// Vector of bytes of unknown size.
	///
	/// solidity name: bytes
	/// Encoded in two parts.
	/// Init part: offset of 'closing part`.
	/// Closing part: encoded length followed by encoded right padded bytes.
	Bytes(Vec<u8>),
	/// Signed integer.
	///
	/// solidity name: int
	Int(Int),
	/// Unsigned integer.
	///
	/// solidity name: uint
	Uint(Uint),
	/// Boolean value.
	///
	/// solidity name: bool
	/// Encoded as left padded [0u8; 32], where last bit represents boolean value.
	Bool(bool),
	/// String.
	///
	/// solidity name: string
	/// Encoded in the same way as bytes. Must be utf8 compliant.
	String(String),
	/// Array with known size.
	///
	/// solidity name eg.: int[3], bool[3], address[][8]
	/// Encoding of array is equal to encoding of consecutive elements of array.
	FixedArray(Vec<Token>),
	/// Array of params with unknown size.
	///
	/// solidity name eg. int[], bool[], address[5][]
	Array(Vec<Token>),
	/// Tuple of params of variable types.
	///
	/// solidity name: tuple
	Tuple(Vec<Token>),
}


impl Token {
    pub fn is_dynamic(&self) -> bool {
		match self {
			Token::Bytes(_) | Token::String(_) | Token::Array(_) => true,
			Token::FixedArray(tokens) => tokens.iter().any(|token| token.is_dynamic()),
			Token::Tuple(tokens) => tokens.iter().any(|token| token.is_dynamic()),
			_ => false,
		}
	}
}



pub(crate) fn encode(tokens: &[Token]) -> Vec<u8> {
	let mediates = &tokens.iter().map(mediate_token).collect::<Vec<_>>();
	encode_head_tail(mediates).into_iter().flatten().collect()
}



pub(crate) fn encode_data(
    primary_type: &str,
    data: &serde_json::Value,
    types: &Eip712Types,
) -> Result<Vec<Token>, AuthError> {
    
    let hash = hash_type(primary_type, types)?;
    let mut tokens = vec![Token::Uint(U256::from(hash))];

    if let Some(fields) = types.get(primary_type) {

        for field in fields {

			if let Value::Map(map) = &data {
				// handle recursive types
				if let Some(value) = map.get(&Value::String(field.name.clone())) {
					let field = encode_field(types, &field.name, &field.r#type, value)?;
					tokens.push(field);
				} else if types.contains_key(&field.r#type) {
					tokens.push(Token::Uint(U256::zero()));
				} else {
					return Err(AuthError::generic(format!("No data found for: `{}`", field.name)))
				}
			} else {
				return Err(AuthError::generic("expected object for eip712 data"));
			}

        }
    }

    Ok(tokens)
}



fn hash_type(primary_type: &str, types: &Eip712Types) -> Result<[u8; 32], AuthError> {
    encode_type(primary_type, types).map(|s| keccak256(s.as_bytes()))
}



fn encode_type(
    primary_type: &str, 
    types: &Eip712Types
) -> Result<String, AuthError> {
    let mut names = BTreeSet::new();
    find_type_dependencies(primary_type, types, &mut names);
    names.remove(primary_type);
    let mut deps: Vec<_> = names.into_iter().collect();
    deps.insert(0, primary_type);

    let mut res = String::new();

    for dep in deps.into_iter() {
        let fields = types.get(dep).ok_or_else(|| {
            AuthError::generic(format!("No type definition found for: `{dep}`"))
        })?;

        res += dep;
        res.push('(');
        res += &fields
            .iter()
            .map(|ty| format!("{} {}", ty.r#type, ty.name))
            .collect::<Vec<_>>()
            .join(",");

        res.push(')');
    }
    Ok(res)
}



fn find_type_dependencies<'a>(
    primary_type: &'a str,
    types: &'a Eip712Types,
    found: &mut BTreeSet<&'a str>,
) {
    if found.contains(primary_type) {
        return
    }
    if let Some(fields) = types.get(primary_type) {
        found.insert(primary_type);
        for field in fields {
            // need to strip the array tail
            let ty = field.r#type.split('[').next().unwrap();
            find_type_dependencies(ty, types, found)
        }
    }
}





fn encode_field(
    types: &Eip712Types,
    _field_name: &str,
    field_type: &str,
    value: &serde_json::Value,
) -> Result<Token, AuthError> {
    let token = {
        // check if field is custom data type
        if types.contains_key(field_type) {
            let tokens = encode_data(field_type, value, types)?;
            let encoded = encode(&tokens);
            Token::Uint(U256::from(keccak256(&encoded)))
        } else {
            match field_type {
                s if s.contains('[') => {
                    let (stripped_type, _) = s.rsplit_once('[').unwrap();
                    // ensure value is an array
					let values = if let Value::Seq(values) = value {
						values
					} else {
						return Err(AuthError::generic(format!(
							"Expected array for type `{s}`, but got someting else for field `{_field_name}`",
						)));
					};
                    let tokens = values
                        .iter()
                        .map(|value| encode_field(types, _field_name, stripped_type, value))
                        .collect::<Result<Vec<_>, _>>()?;

                    let encoded = encode(&tokens);
                    Token::Uint(U256::from(keccak256(&encoded)))
                }
                s => {
                    match s {
                        "address" => {
                            Token::Address(value.clone().deserialize_into()?)
                        },
                        "string" => {
                            let s: String = value.clone().deserialize_into()?;
                            Token::Uint(U256::from(keccak256(s.as_bytes())))
                        },
                        "uint256" => {
                            let val: MaybeStringU256 = value.clone().deserialize_into()?;
                            let val = val.try_into().map_err(|err| {
                                AuthError::generic(format!("Failed to parse uint {err}"))
                            })?;
                            Token::Uint(val)
                        },
                        "bytes32" => {
                            let data : Vec<u8> = match value {
                                Value::String(s) => hex::decode(s.trim_start_matches("0x"))
                                    .map_err(|err| AuthError::generic(format!("Failed to decode hex: {err}")))?,
                                v => v.clone().deserialize_into()?,
                            };
                            Token::Uint(U256::from(&data[..]))
                        }
                        _ =>  {
                            return Err(AuthError::generic(format!(
                                "Unsupported type `{s}` for field `{_field_name}`",
                            )))
                        }
                    }
                }
            }
        }
    };

    Ok(token)
}





impl Mediate<'_> {
	fn head_len(&self) -> u32 {
		match self {
			Mediate::Raw(len, _) => 32 * len,
			Mediate::RawArray(ref mediates) => mediates.iter().map(|mediate| mediate.head_len()).sum(),
			Mediate::Prefixed(_, _) | Mediate::PrefixedArray(_) | Mediate::PrefixedArrayWithLength(_) => 32,
		}
	}

    fn tail_len(&self) -> u32 {
		match self {
			Mediate::Raw(_, _) | Mediate::RawArray(_) => 0,
			Mediate::Prefixed(len, _) => 32 * len,
			Mediate::PrefixedArray(ref mediates) => mediates.iter().fold(0, |acc, m| acc + m.head_len() + m.tail_len()),
			Mediate::PrefixedArrayWithLength(ref mediates) => {
				mediates.iter().fold(32, |acc, m| acc + m.head_len() + m.tail_len())
			}
		}
	}

	fn head_append(&self, acc: &mut Vec<Word>, suffix_offset: u32) {
		match *self {
			Mediate::Raw(_, raw) => encode_token_append(acc, raw),
			Mediate::RawArray(ref raw) => raw.iter().for_each(|mediate| mediate.head_append(acc, 0)),
			Mediate::Prefixed(_, _) | Mediate::PrefixedArray(_) | Mediate::PrefixedArrayWithLength(_) => {
				acc.push(pad_u32(suffix_offset))
			}
		}
	}


	fn tail_append(&self, acc: &mut Vec<Word>) {
		match *self {
			Mediate::Raw(_, _) | Mediate::RawArray(_) => {}
			Mediate::Prefixed(_, raw) => encode_token_append(acc, raw),
			Mediate::PrefixedArray(ref mediates) => encode_head_tail_append(acc, mediates),
			Mediate::PrefixedArrayWithLength(ref mediates) => {
				// + 32 added to offset represents len of the array prepended to tail
				acc.push(pad_u32(mediates.len() as u32));
				encode_head_tail_append(acc, mediates);
			}
		};
	}
}




fn encode_head_tail(mediates: &[Mediate]) -> Vec<Word> {
	let (heads_len, tails_len) =
		mediates.iter().fold((0, 0), |(head_acc, tail_acc), m| (head_acc + m.head_len(), tail_acc + m.tail_len()));

	let mut result = Vec::with_capacity((heads_len + tails_len) as usize);
	encode_head_tail_append(&mut result, mediates);

	result
}


fn encode_head_tail_append(acc: &mut Vec<Word>, mediates: &[Mediate]) {
	let heads_len = mediates.iter().fold(0, |head_acc, m| head_acc + m.head_len());

	let mut offset = heads_len;
	for mediate in mediates {
		mediate.head_append(acc, offset);
		offset += mediate.tail_len();
		mediate.tail_append(acc);
	}
}


fn mediate_token(token: &Token) -> Mediate<'_> {
	match token {
		Token::Address(_) => Mediate::Raw(1, token),
		Token::Bytes(bytes) => Mediate::Prefixed(pad_bytes_len(bytes), token),
		Token::String(s) => Mediate::Prefixed(pad_bytes_len(s.as_bytes()), token),
		Token::FixedBytes(bytes) => Mediate::Raw(((bytes.len() + 31) / 32) as u32, token),
		Token::Int(_) | Token::Uint(_) | Token::Bool(_) => Mediate::Raw(1, token),
		Token::Array(ref tokens) => {
			let mediates = tokens.iter().map(mediate_token).collect();

			Mediate::PrefixedArrayWithLength(mediates)
		}
		Token::FixedArray(ref tokens) | Token::Tuple(ref tokens) => {
			let mediates = tokens.iter().map(mediate_token).collect();

			if token.is_dynamic() {
				Mediate::PrefixedArray(mediates)
			} else {
				Mediate::RawArray(mediates)
			}
		}
	} 
}



#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum MaybeStringU256 {
    String(String),
    U256(U256),
    Num(u64),
}

impl TryFrom<MaybeStringU256> for U256 {
    type Error = String;
    fn try_from(value: MaybeStringU256) -> Result<Self, Self::Error> {
        match value {
            MaybeStringU256::U256(n) => Ok(n),
            MaybeStringU256::Num(n) => Ok(U256::from(n)),
            MaybeStringU256::String(s) => {
                if let Ok(val) = s.parse::<u128>() {
                    Ok(val.into())
                } else if s.starts_with("0x") {
                    U256::from_str(&s).map_err(|e| e.to_string())
                } else {
                    U256::from_dec_str(&s).map_err(|e| e.to_string())
                }
            }
        }
    }
}






#[derive(Debug)]
enum Mediate<'a> {
	// head
	Raw(u32, &'a Token),
	RawArray(Vec<Mediate<'a>>),

	// head + tail
	Prefixed(u32, &'a Token),
	PrefixedArray(Vec<Mediate<'a>>),
	PrefixedArrayWithLength(Vec<Mediate<'a>>),
}

fn pad_bytes_len(bytes: &[u8]) -> u32 {
	((bytes.len() + 31) / 32) as u32 + 1
}


fn pad_bytes_append(data: &mut Vec<Word>, bytes: &[u8]) {
	data.push(pad_u32(bytes.len() as u32));
	fixed_bytes_append(data, bytes);
}

fn pad_u32(value: u32) -> Word {
	let mut padded = [0u8; 32];
	padded[28..32].copy_from_slice(&value.to_be_bytes());
	padded
}



fn fixed_bytes_append(result: &mut Vec<Word>, bytes: &[u8]) {
	let len = (bytes.len() + 31) / 32;
	for i in 0..len {
		let mut padded = [0u8; 32];

		let to_copy = match i == len - 1 {
			false => 32,
			true => match bytes.len() % 32 {
				0 => 32,
				x => x,
			},
		};

		let offset = 32 * i;
		padded[..to_copy].copy_from_slice(&bytes[offset..offset + to_copy]);
		result.push(padded);
	}
}


fn encode_token_append(data: &mut Vec<Word>, token: &Token) {
	match *token {
		Token::Address(ref address) => {
			let mut padded = [0u8; 32];
			padded[12..].copy_from_slice(address.as_ref());
			data.push(padded);
		}
		Token::Bytes(ref bytes) => pad_bytes_append(data, bytes),
		Token::String(ref s) => pad_bytes_append(data, s.as_bytes()),
		Token::FixedBytes(ref bytes) => fixed_bytes_append(data, bytes),
		Token::Int(int) => data.push(int.into()),
		Token::Uint(uint) => data.push(uint.into()),
		Token::Bool(b) => {
			let mut value = [0u8; 32];
			if b {
				value[31] = 1;
			}
			data.push(value);
		}
		_ => panic!("Unhandled nested token: {:?}", token),
	};
}


