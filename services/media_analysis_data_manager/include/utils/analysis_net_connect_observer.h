/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef OHOS_ANALYSIS_NET_CONNECT_OBSERVER_H
#define OHOS_ANALYSIS_NET_CONNECT_OBSERVER_H

#include <atomic>
#include <functional>
#include <mutex>
#include "net_all_capabilities.h"
#include "net_conn_callback_stub.h"

namespace OHOS::Media {
#define EXPORT __attribute__ ((visibility ("default")))

enum class NetBearer : uint32_t {
    NO_NETWORK = 0,
    BEARER_ETHERNET = 1,  // bit 0
    BEARER_WIFI = 2,      // bit 1
    BEARER_CELLULAR = 4,  // bit 2
    BEARER_ALL = 0xFFFFFFFF,  // bit all
};

// 图片处理结果
enum class PrepareLcdResult : uint32_t {
    SUCCESS = 0,           // 成功
    NO_NETWORK = 1,        // 无网络
    DOWNLOAD_PROHIBITED = 2,  // 下载被禁止（网络类型不匹配）
    GENERATE_FAILURE = 3,  // 生成失败
    DOWNLOAD_FAILURE = 4,  // 下载失败
    INVALID_PARAM = 5,     // 参数无效
};

// LCD 清理结果
enum class RemoveCloudLcdResult : uint64_t {
    SUCCESS = 0,              // 成功
    FAILED = 1,               // 失败
    RETAINED = 2,             // 保留（满足老化条件）
    NOT_FOUND = 3,            // LCD 图不存在
    THRESHOLD_NOT_REACHED = 4 // 未达到老化阈值
};

class AnalysisNetConnectObserver : public NetManagerStandard::NetConnCallbackStub {
public:
    AnalysisNetConnectObserver() {}
    virtual ~AnalysisNetConnectObserver() = default;

    // NetConnCallbackStub 接口实现
    int32_t NetCapabilitiesChange(sptr<NetManagerStandard::NetHandle> &netHandle,
        const sptr<NetManagerStandard::NetAllCapabilities> &netAllCap) override;
    int32_t NetLost(sptr<NetManagerStandard::NetHandle> &netHandle) override;

    // 设置要求的网络类型
    void SetRequiredNetBearerBitmap(uint32_t netBearerBitmap);

    // 获取当前网络类型 bitmap
    uint32_t GetCurrentNetBearerBitmap() const;

private:
    void SetNetConnStatus(const NetBearer status);
    bool IfNeedCanceled() const;

private:
    NetBearer netStatus_ = NetBearer::NO_NETWORK;
    uint32_t requiredNetBearerBitmap_ = static_cast<uint32_t>(NetBearer::NO_NETWORK);
};

}  // namespace OHOS::Media

#endif  // OHOS_ANALYSIS_NET_CONNECT_OBSERVER_H