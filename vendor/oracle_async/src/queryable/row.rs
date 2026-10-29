use std::sync::Arc;
use crate::error::{Error, Result};
use crate::proto::tns_types::TnsType;
use super::values::{FromValue, OracleValue};

#[derive(Debug, Clone)]
pub struct ColumnMeta {
    pub name: String,
    pub data_type: TnsType,
    pub max_len: usize,
    pub precision: u8,
    pub scale: u8,
    pub allow_null: bool,
    /// 描述时服务器回显的字符集（LOB 预取轮的 define 需回填）
    pub charset_id: u32,
    pub charset_form: u8,
}

#[derive(Debug, Clone)]
pub struct Row {
    pub(crate) columns: Arc<Vec<ColumnMeta>>,
    pub(crate) values: Vec<OracleValue>,
}

impl Row {
    pub fn new(columns: Arc<Vec<ColumnMeta>>, values: Vec<OracleValue>) -> Self {
        Self { columns, values }
    }

    pub fn len(&self) -> usize {
        self.values.len()
    }

    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    pub fn columns(&self) -> &[ColumnMeta] {
        &self.columns
    }

    pub fn values(&self) -> &[OracleValue] {
        &self.values
    }

    pub fn get<T: FromValue>(&self, index: usize) -> Result<T> {
        let val = self
            .values
            .get(index)
            .ok_or_else(|| Error::FromValue(format!("column index {index} out of bounds ({})", self.values.len())))?;
        T::from_value(val.clone())
    }

    pub fn get_by_name<T: FromValue>(&self, col_name: &str) -> Result<T> {
        let idx = self
            .columns
            .iter()
            .position(|c| c.name.eq_ignore_ascii_case(col_name))
            .ok_or_else(|| Error::FromValue(format!("column name '{col_name}' not found")))?;
        self.get(idx)
    }

    pub fn take_values(self) -> Vec<OracleValue> {
        self.values
    }
}
