//! A custom derive (procedural macro) implementation for `derive(Parametrize)` used in the
//! `runner` for keeping track of experimental settings.

extern crate proc_macro;

use proc_macro2::TokenStream;

use quote::{quote, quote_spanned};

use syn::{parse_macro_input, spanned::Spanned, AttrStyle, Data, DeriveInput, Fields};

#[proc_macro_derive(Parametrize, attributes(name, timestamp))]
pub fn derive(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    // Parse the tokens as a syntax tree.
    let input = parse_macro_input!(input as DeriveInput);

    let struct_id = input.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    let important = important(&input.data);
    let timestamp = timestamp(&input.data);

    // Build the output.
    let expanded = quote! {
        impl #impl_generics Parametrize for #struct_id #ty_generics #where_clause {
            fn important(&self) -> Vec<(String, String)> {
                #important
            }

            fn timestamp(&self) -> &crate::output::Timestamp {
                #timestamp
            }
        }
    };

    proc_macro::TokenStream::from(expanded)
}

/// Generate an expression that stringifies the fields and serializes their values.
fn important(data: &Data) -> TokenStream {
    match *data {
        Data::Struct(ref data) => match data.fields {
            Fields::Named(ref fields) => {
                let recurse = fields.named.iter().map(|f| {
                    let name = &f.ident;

                    // We need to check if the field is important or conditionally important.
                    get_importance(&f).map(|(important, maybe_important, condition)| {
                        quote_spanned! { f.span() =>
                            if #important || (#maybe_important && #condition) {
                                let name = stringify!(#name);
                                let value = serde_json::to_string(&self.#name)
                                    .expect("unable to serialize");

                                important.push((name.into(), value.into()));
                            }
                        }
                    })
                });

                quote! {
                    let mut important = Vec::new();
                    #(#recurse)*
                    important
                }
            }
            _ => {
                panic!("struct with derived `Parametrize` must have named fields");
            }
        },

        _ => {
            panic!("`Parametrize`d type must be a struct.");
        }
    }
}

/// Returns `(important, maybe_important, condition)` where
/// - `important` is true iff this field is unconditionally important,
/// - `maybe_important` is true iff this field conditionally important,
/// - `condition` is the condition under which the field is conditionally important, if any.
fn get_importance(field: &syn::Field) -> Option<(bool, bool, TokenStream)> {
    // Look through the attributes for `name`.
    for attr in &field.attrs {
        if let AttrStyle::Outer = attr.style {
            if attr.path.is_ident("name") {
                if attr.tokens.is_empty() {
                    return Some((true, false, quote!(false)));
                } else {
                    return Some((false, true, attr.tokens.clone()));
                }
            }
        }
    }

    return None;
}

/// Returns the field that is the timestamp of the type.
fn timestamp(data: &Data) -> TokenStream {
    match *data {
        Data::Struct(ref data) => match data.fields {
            Fields::Named(ref fields) => {
                let field = fields
                    .named
                    .iter()
                    .find(|f| {
                        for attr in &f.attrs {
                            if let AttrStyle::Outer = attr.style {
                                if attr.path.is_ident("timestamp") {
                                    if attr.tokens.is_empty() {
                                        return true;
                                    }
                                }
                            }
                        }
                        false
                    })
                    .expect("need to have a field of type `Timestamp` tagged with #[timestamp]");

                let name = &field.ident;

                quote_spanned! { name.span() => & self . #name }
            }
            _ => {
                panic!("struct with derived `Parametrize` must have named fields");
            }
        },

        _ => {
            panic!("`Parametrize`d type must be a struct.");
        }
    }
}
