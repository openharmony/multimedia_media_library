/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef OHOS_MEDIA_CLOUD_SYNC_ERROR_H
#define OHOS_MEDIA_CLOUD_SYNC_ERROR_H

#include <iostream>
#include <vector>

#define EXPORT __attribute__ ((visibility ("default")))

namespace OHOS::Media::CloudSync {
enum class MDKLocalErrorCode {
    NO_ERROR = 0,
    IPC_CONNECT_FAILED,
    IPC_SEND_FAILED,
    DATA_TYPE_ERROR,
    ACCESS_DENIED,            // 没有权限访问记录、数据库等
    ATOMIC_ERROR,             // 原子批处理操作失败
    AUTHENTICATION_FAILED,    // 身份验证失败
    AUTHENTICATION_REQUIRED,  // 没有验证身份，但请求需要身份验证
    BAD_REQUEST,              // 无效的请求
    CONFLICT,                 // recordChangeTag值过期
    EXISTS,                   // 创建的资源已存在
    INTERNAL_ERROR,           // 内部错误
    NOT_FOUND,                // 资源未找到
    QUOTA_EXCEEDED,  // 如果访问公共数据库，您超出了应用程序的配额。访问私有数据库时，超出用户的iCloud配额
    SIGN_IN_FAILED,  // 用户登录失败
    THROTTLED,       // 请求被停止了，稍后重试
    TRY_AGAIN_LATER,               // 内部错误，稍后重试
    VALIDATING_REFERENCE_ERROR,    // 请求违反了验证引用约束
    UNIQUE_FIELD_ERROR,            // 服务器拒绝请求，因为与唯一字段有冲突
    ZONE_NOT_FOUND,                // 没有找到请求中指定的区域
    UNKNOWN_ERROR,                 // 发生未知错误
    NETWORK_ERROR,                 // 网络错误，比如连接超时
    SERVICE_UNAVAILABLE,           // 无法联系到DriveKit服务。
    INVALID_ARGUMENTS,             // 无效的参数
    UNEXPECTED_SERVER_RESPONSE,    // DriveKit解析不了服务器返回的信息
    CONFIGURATION_ERROR,           // DriveKit配置错误，比如没有配置容器
    SHARE_UI_TIMEOUT,              // 共享界面加载失败超时
    BAD_ALLOC_MEMORY,              // 申请内存失败
    LOCAL_SPACE_FULL,              // 本地空间不足
    TASK_CANCEL_FAIL,              // 取消任务失败
    TASK_CANCEL,                   // 任务取消
    DECRYPT_FAIL,                  // 解密失败
    OPEN_FILE_FAIL,                // 打开文件失败
    DELETE_FILE_FAIL,              // 删除文件失败
    INIT_DECRYPT_FAIL,             // 初始化解密失败
    DOWNLOAD_REQUEST_ERROR,        // 网络请求失败
    GET_DECRYPTKEY_FAIL,           // 获取密钥失败
    GET_ASSET_FAIL,                // 获取资产信息失败
    CREAT_TEMP_FILE_FAIL,          // 创建下载所需临时文件失败
    ADD_SLICE_TASK_FAIL,           // 添加分片任务失败
    SYNC_SWITCH_OFF,               // 云空间同步开关关闭状态
    DOWNLOAD_PATH_ERROR,           // 资产下载路径错误
    PREAD_MULTI_SLICE_NO_SUPPORT,  // 多分片暂不支持PREAD接口
    RENAME_TEMPFILE_FAIL,          // 重命名临时文件失败
    SLICE_NOT_DOWN_ALL,            // 分片未全部下载完毕
    RETRY_TASK_DOWNLOAD_FAIL,      // 重试失败
    CREAT_ZERO_FILE_FAIL,          // 创建0字节文件失败
    MEMCPYS_FAIL_READBUFF_ERROR,   // ReadFileStreamVec执行memcpy_s时返回非0 入参异常 请重试
    ASSETVEC_PARA_REPETE,          // 参数数组有重复项
    CHECK_VALIDITY_FAIL,           // 校验有效性失败
    POWER_DENIED,                  // 电量管控，拒绝访问
    MERGE_FILE_FAIL,               // 文件合并失败
};

enum class MDKErrorType {
    TYPE_UNKNOWN = 0,
    TYPE_NOT_NEED_RETRY,  // 不需要重试的错误类型
    TYPE_NEED_UPLOAD,     // 需要重新上传
    TYPE_MAX,
};

struct MDKErrorDetail {
    std::string domain;       // 描述:[域];
    std::string reason;       // 描述:[错误原因];
    std::string errorCode;    // 描述:[系统内部错误编码, 参见错误码规范]，26004977、31004913等;
    std::string description;  // 描述:[错误描述信息];
    std::string errorPos;     // 描述:[错误位置类型];
    std::string errorParam;   // 描述:[错误位置];
    int detailCode;           // 描述:[错误编码, 参见DKDetailErrorCode];
};

class EXPORT MDKError {
public:
    // 是否有错误
    bool HasError() const
    {
        return isLocalError || isServerError;
    }
    MDKErrorType GetErrorType() const
    {
        return errorType;
    }

public:
    void SetLocalError(MDKLocalErrorCode code)
    {
        if (code == MDKLocalErrorCode::NO_ERROR) {
            isLocalError = false;
        } else {
            isLocalError = true;
        }
        dkErrorCode = code;
    }
    void SetServerError(int code)
    {
        isServerError = true;
        serverErrorCode = code;
    }

public:
    bool isLocalError = false;                            // 是否为本地错误
    MDKLocalErrorCode dkErrorCode;                        // 本地错误码
    bool isServerError = false;                           // 是否为服务端错误
    int serverErrorCode;                                  // 服务端错误码
    std::string reason;                                   // DkErrorCode或者serverErrorCode的描述
    std::vector<MDKErrorDetail> errorDetails;             // 错误具体信息   遗留待定
    int retryAfter;                                       // 再次尝试此操作之前的建议等待时间
    MDKErrorType errorType = MDKErrorType::TYPE_UNKNOWN;  // 错误类型
};
}  // namespace OHOS::Media::CloudSync
#endif