/*
* Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
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