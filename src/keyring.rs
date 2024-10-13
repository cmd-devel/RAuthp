use std::{collections::HashMap, fmt};
use tokio::runtime::Runtime;

// TODO: Use async?

pub struct Keyring {
    keyring: oo7::Keyring,
    runtime: Runtime,
}

pub struct Secret {
    name: String,
    secret: String,
}

impl Secret {
    fn new(name: &str, secret: &[u8]) -> Self {
        Self {
            name: String::from(name),
            secret: String::from_utf8(secret.to_vec()).unwrap(),
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn secret(&self) -> &str {
        &self.secret
    }
}

#[derive(Debug, Clone)]
pub struct KeyringError {
    msg: String,
}

impl KeyringError {
    fn from_slice(msg: &str) -> Self {
        Self {
            msg: String::from(msg),
        }
    }
    fn from_string(msg: String) -> Self {
        Self { msg }
    }
}

impl fmt::Display for KeyringError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Keyring error: {}", self.msg)
    }
}

impl Keyring {
    const ATTRIBUTE_KEY: &'static str = "rauthp_secret_id";
    const COMMON_ATTRIBUTE_KEY: &'static str = "application_id";
    const COMMON_ATTRIBUTE_VALUE: &'static str = "25fa6cf5-ba20-481d-b382-f3acab4da54e";

    pub fn new() -> Result<Self, KeyringError> {
        let runtime = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(r) => r,
            Err(e) => {
                return Err(KeyringError::from_string(e.to_string()));
            }
        };

        let keyring = match runtime.block_on(oo7::Keyring::new()) {
            Ok(k) => k,
            Err(e) => {
                return Err(KeyringError::from_string(e.to_string()));
            }
        };

        Ok(Keyring { keyring, runtime })
    }

    fn secret_attributes(name: &str) -> HashMap<&str, &str> {
        let mut result = Self::secrets_common_attribute();
        result.insert(Self::ATTRIBUTE_KEY, name);
        result
    }

    fn secrets_common_attribute() -> HashMap<&'static str, &'static str> {
        HashMap::from([(Self::COMMON_ATTRIBUTE_KEY, Self::COMMON_ATTRIBUTE_VALUE)])
    }

    pub fn store_secret(&self, name: &str, secret: &str) -> Result<(), KeyringError> {
        match self.get_secret(name) {
            Ok(s) => {
                if s.is_some() {
                    return Err(KeyringError::from_slice("Secret already exists"));
                }
            }
            Err(e) => {
                return Err(e);
            }
        }

        let attributes = Self::secret_attributes(name);
        match self
            .runtime
            .block_on(self.keyring.create_item(name, &attributes, secret, false))
        {
            Ok(()) => Ok(()),
            Err(e) => Err(KeyringError::from_string(e.to_string())),
        }
    }

    pub fn delete_secret(&self, name: &str) -> Result<(), KeyringError> {
        let attributes = Self::secret_attributes(name);
        match self.runtime.block_on(self.keyring.delete(&attributes)) {
            Ok(()) => Ok(()),
            Err(e) => Err(KeyringError::from_string(e.to_string())),
        }
    }

    pub fn get_all_secrets(&self) -> Result<Vec<Secret>, KeyringError> {
        let attributes = Self::secrets_common_attribute();
        let request_result = self
            .runtime
            .block_on(self.keyring.search_items(&attributes));

        match request_result {
            Ok(secrets) => secrets
                .iter()
                .map(|elt| {
                    let Ok(secret) = self.runtime.block_on(elt.secret()) else {
                        return Err(KeyringError::from_slice(
                            "Failed to retrieve the value of a secret",
                        ));
                    };
                    let Ok(attr) = self.runtime.block_on(elt.attributes()) else {
                        return Err(KeyringError::from_slice(
                            "Failed to retrive the name of a secret",
                        ));
                    };
                    let Some(name) = attr.get(Self::ATTRIBUTE_KEY) else {
                        return Err(KeyringError::from_slice(
                            "Unexpected data retrieved from the keyring",
                        ));
                    };
                    Ok(Secret::new(name, &secret))
                })
                .collect::<Result<Vec<Secret>, _>>(),
            Err(e) => Err(KeyringError::from_string(e.to_string())),
        }
    }

    pub fn get_secret(&self, name: &str) -> Result<Option<Secret>, KeyringError> {
        let attributes = Self::secret_attributes(name);
        match self
            .runtime
            .block_on(self.keyring.search_items(&attributes))
        {
            Ok(request_result) => {
                if request_result.is_empty() {
                    return Ok(None);
                }

                if request_result.len() > 1 {
                    return Err(KeyringError::from_slice("Too many results"));
                }

                let Ok(secret) = self
                    .runtime
                    .block_on(request_result.get(0).unwrap().secret())
                else {
                    return Err(KeyringError::from_slice("Failed the value of the secret"));
                };
                Ok(Some(Secret::new(name, &secret)))
            }
            Err(e) => Err(KeyringError::from_string(e.to_string())),
        }
    }
}
