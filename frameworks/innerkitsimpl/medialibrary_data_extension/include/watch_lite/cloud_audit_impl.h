/*
* Copyright (C) 2026 Huawei Device Co., Ltd.
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

#ifndef CLOUD_AUDIT_IMPL_H
#define CLOUD_AUDIT_IMPL_H

#include "cloud_audit_callback.h"

namespace OHOS {
namespace WatchSystemService {

class CloudAuditImpl {
public:
    /**
     * 获取 CloudAuditImpl 单例实例（C++ 接口）
     *
     * @return 引用指向唯一实例
     */
    static CloudAuditImpl &GetInstance();

    /**
     * 获取 CloudAuditImpl 单例实例（C 兼容接口）
     *
     * @return 指向唯一实例的指针，永不为 nullptr
     */
    static CloudAuditImpl *GetCloudAuditInstance();

    /**
     * 注册云审计连接回调
     *
     * @param callback 回调对象，不能为空
     * @return 注册成功返回 0；失败返回 -1
     */
    virtual int32_t RegisterCloudAuditCallback(std::shared_ptr<CloudAuditCallback> callback);

    /**
     * 解注册云审计连接回调
     *
     * @return 成功返回 0；失败返回 -1
     */
    virtual int32_t UnRegisterCloudAuditCallback();

    /**
     * 通过配置项名称获取配置值
     *
     * @param type       配置类型：1=用户配置，2=默认配置
     * @param configKey  配置项名称
     * @param configValue 输出：获取到的配置值（安全字符串）
     * @return 成功返回 0；失败返回 -1
     */
    virtual int32_t GetConfigValueByName(
        int32_t type, const std::string &configKey, std::string &configValue);

    /**
     * 上传图片信息进行风控审计
     *
     * @param type       媒体资源类型：1=图片，2=视频
     * @param uri  媒体资源的uri
     * @param displayName 媒体资源的name
     * @return 成功返回 0；失败返回 -1
     */
    virtual int32_t UploadInfoToAudit(int32_t type, std::string &uri, std::string &displayName);

private:
    CloudAuditImpl() = default;
    ~CloudAuditImpl() = default;

    // 禁止拷贝和赋值
    CloudAuditImpl(const CloudAuditImpl&) = delete;
    CloudAuditImpl& operator=(const CloudAuditImpl&) = delete;
};
}  // namespace WatchSystemService
}  // namespace OHOS
#endif