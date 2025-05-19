use std::fmt::Display;

use quote::ToTokens;
use syn::{
    parse::{Parse, ParseStream}, parse_quote, punctuated::Punctuated, Meta, Token
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



macro_rules! bail {
    ($span_src:expr, $msg:literal) => {{
        return Err($crate::utils::error_message!($span_src, $msg));
    }};
}


macro_rules! error_message {
    ($span_src:expr, $msg:literal) => {{
        ::syn::Error::new(::syn::spanned::Spanned::span(&{ $span_src }), $msg)
    }};
}

#[derive(Debug, Clone)]
pub struct Options {
    pub crate_path: syn::Path,
    pub no_deny : bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            crate_path: parse_quote!(::saa_schema),
            no_deny: false,
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
            let path = param.path();
            if path.is_ident("crate") {
                let path_as_string: syn::LitStr = syn::parse2(param.to_token_stream())?;
                acc.crate_path = path_as_string.parse()?
            } else if path.is_ident("no_deny") {
                acc.no_deny = true;
            } else {
                bail!(param, "unknown option");
            }
        }
        Ok(acc)
    }
}

pub(crate) use bail;
pub(crate) use error_message;
pub(crate) use fallible_macro;