//! TTC Summary 对象（MsgCode 4）解析——go-ora NewSummary 的逐字段移植。
//! 字段集随会话能力位伸缩：EOS（服务器 caps[15]&1）追加 EndOfCallStatus，
//! FSAP（caps[16]&1，且 TTC>=3）追加 EndToEndECIDSequence；TTC>=7 走另一
//! 尾段（本实现按 TTC<7 的三 DLC 尾段移植——实际协商 TTC 版本由类型协商
//! min(客户端 11, 服务器 caps[7]) 决定）。
//!
//! 全部经 Conn 的动态读取原语（read_ci/read_dlc/read_clr：peek 首字节定
//! 实际长度再按需补包）——Summary 常正好落在 DATA 包尾，任何按字段上限
//! 预读都会等一个永不到来的下一包。

use log::trace;
use crate::conn::Conn;
use crate::error::Result;

#[derive(Debug, Default)]
pub struct Summary {
    pub ret_code: i32,
    pub cursor_id: u16,
    pub cur_row_number: u32,
    pub error_message: Option<Vec<u8>>,
}

pub async fn read_summary(conn: &mut Conn) -> Result<Summary> {
    let mut end_of_call = 0i64;
    if conn.has_eos_capability {
        end_of_call = conn.read_ci(4).await?;
    }
    if conn.ttc_version >= 3 && conn.has_fsap_capability {
        let _ecid = conn.read_ci(2).await?;
    }

    let cur_row_number = conn.read_ci(4).await? as u32;
    let ret_code = conn.read_ci(2).await? as i32;
    let _array_elm_werror = conn.read_ci(2).await?;
    let _array_elm_errno = conn.read_ci(2).await?;
    let cursor_id = conn.read_ci(2).await? as u16;
    let _error_pos = conn.read_ci(2).await?;
    let _sql_type = conn.get_byte().await?;
    let _oer_fatal = conn.get_byte().await?;
    if conn.ttc_version >= 4 {
        let _flags = conn.read_ci(2).await?;
        let _user_cursor_opt = conn.read_ci(2).await?;
    } else {
        let _ = conn.get_byte().await?;
        let _ = conn.get_byte().await?;
    }
    let _upi_param = conn.get_byte().await?;
    let _warning_flag = conn.get_byte().await?;
    let _rba = conn.read_ci(4).await?;
    let _partition_id = conn.read_ci(2).await?;
    let _table_id = conn.get_byte().await?;
    let _block_number = conn.read_ci(4).await?;
    let _slot_number = conn.read_ci(2).await?;
    let _os_error = conn.read_ci(4).await?;
    let _stmt_number = conn.get_byte().await?;
    let _call_number = conn.get_byte().await?;
    let _pad1 = conn.read_ci(2).await?;
    let _success_iter = conn.read_ci(4).await?;
    let _ = conn.read_dlc().await?; // unused DLC

    if conn.ttc_version < 7 {
        let _ = conn.read_dlc().await?;
        let _ = conn.read_dlc().await?;
        let _ = conn.read_dlc().await?;
    }

    trace!(
        "Summary: ret_code={ret_code}, cursor={cursor_id}, rows={cur_row_number}, eoc={end_of_call}"
    );

    let error_message = if ret_code != 0 {
        conn.read_clr().await?
    } else {
        None
    };

    Ok(Summary {
        ret_code,
        cursor_id,
        cur_row_number,
        error_message,
    })
}

/// MsgCode 9（EndOfCall）：EOS/FSAP 能力位下的两个尾随字段
pub async fn read_end_of_call(conn: &mut Conn) -> Result<()> {
    if conn.has_eos_capability {
        let _ = conn.read_ci(4).await?;
    }
    if conn.has_fsap_capability {
        let _ = conn.read_ci(2).await?;
    }
    Ok(())
}
