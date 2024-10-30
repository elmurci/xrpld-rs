use crate::structs::st_object::StObject;

#[derive(Clone, Debug)]
#[repr(u8)]
pub enum XrplObject {
    ValidationMessage(StObject),
}