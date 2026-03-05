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

#ifndef CLOUD_AUDIT_CALLBACK
#define CLOUD_AUDIT_CALLBACK

namespace OHOS {
namespace WatchSystemService {

/**
 * 风控结果的回调
 */
class CloudAuditCallback {
public:

    /**
     * 接受数据的回调
     *
     * @param msg 收到的对端数据
     */
    virtual void OnReceiveData(const std::string &msg, int32_t type) = 0;

    /**
     * 接受数据的回调
     *
     * @param key 数据库中的关键字
     * @param values 数据库中的值
     */
    virtual void OnReceiveConfigData(const std::string &key, const std::string &values) = 0;

    virtual ~CloudAuditCallback() = default;
};
}  // namespace WatchSystemService
}  // namespace OHOS

#endif