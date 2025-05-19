use std::fmt::Display;
use quote::ToTokens;
use syn::{
    parse::{Parse, ParseStream}, parse_quote, punctuated::Punctuated, Lit, Meta, Token
};


macro_rules! fallible_macro {
    (
        $(
            #[ $( $attribute_decl:tt )* ]
        )*
        pub fn $macro_name:ident ( $( $params:tt )* ) -> syn::Result<$inner_return:path> {
            $( $fn_body:tt )*
        }
    ) => {
        $(
            #[ $( $attribute_decl )* ]
        )*
        pub fn $macro_name ( $( $params )* ) -> $inner_return {
            let result = move || -> ::syn::Result<_> {
                $( $fn_body )*
            };

            match result() {
                Ok(val) => val,
                Err(err) => err.into_compile_error().into(),
            }
        }
    }
}


#[derive(Debug, Clone)]
pub struct Options {
    pub crate_path: syn::Path,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            crate_path: parse_quote!(::saa_schema),
        }
    }
}

impl Display for Options {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "crate_path: {}", self.crate_path.to_token_stream())
    }
}


impl Parse for Options {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let mut acc = Self::default();
        let params = Punctuated::<Meta, Token![,]>::parse_terminated(input)?;
        for param in params {
            match param {
                Meta::NameValue(nv) => {
                    if nv.path.is_ident("crate") {
                        if let Lit::Str(s) = nv.lit {
                            acc.crate_path = s.parse()?;
                        } else {
                            return Err(syn::Error::new_spanned(nv.lit, "expected string literal"));
                        }
                    } else {
                        return Err(syn::Error::new_spanned(nv.path, "unknown option"));
                    }
                }
                _ => {
                    return Err(syn::Error::new_spanned(param, "expected `key = \"value\"` format"));
                }
            }
        }
        Ok(acc)
    }
}

pub(crate) use fallible_macro;