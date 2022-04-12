/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "mediadata_connection.h"

#include "ability_manager_client.h"
#include "mediadata_proxy.h"
#include "hilog_wrapper.h"

namespace OHOS {
namespace AppExecFwk {
sptr<MediaDataConnection> MediaDataConnection::instance_ = nullptr;
std::mutex MediaDataConnection::mutex_;

/**
 * @brief get singleton of Class MediaDataConnection
 *
 * @return The singleton of MediaDataConnection
 */
sptr<MediaDataConnection> MediaDataConnection::GetInstance()
{
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (instance_ == nullptr) {
            instance_ = sptr<MediaDataConnection>(new (std::nothrow) MediaDataConnection());
        }
    }
    return instance_;
}

/**
 * @brief This method is called back to receive the connection result after an ability calls the
 * ConnectAbility method to connect it to an extension ability.
 *
 * @param element: Indicates information about the connected extension ability.
 * @param remote: Indicates the remote proxy object of the extension ability.
 * @param resultCode: Indicates the connection result code. The value 0 indicates a successful connection, and any
 * other value indicates a connection failure.
 */
void MediaDataConnection::OnAbilityConnectDone(
    const AppExecFwk::ElementName &element, const sptr<IRemoteObject> &remoteObject, int resultCode)
{
    HILOG_INFO("%{public}s called begin", __func__);
    if (remoteObject == nullptr) {
        HILOG_ERROR("MediaDataConnection::OnAbilityConnectDone failed, remote is nullptr");
        return;
    }
    mediaDataProxy_ = iface_cast<MediaDataProxy>(remoteObject);
    if (mediaDataProxy_ == nullptr) {
        HILOG_ERROR("MediaDataConnection::OnAbilityConnectDone failed, mediaDataProxy_ is nullptr");
        return;
    }
    isConnected_.store(true);
    HILOG_INFO("%{public}s called end", __func__);
}

/**
 * @brief This method is called back to receive the disconnection result after the connected extension ability crashes
 * or is killed. If the extension ability exits unexpectedly, all its connections are disconnected, and each ability
 * previously connected to it will call onAbilityDisconnectDone.
 *
 * @param element: Indicates information about the disconnected extension ability.
 * @param resultCode: Indicates the disconnection result code. The value 0 indicates a successful disconnection, and
 * any other value indicates a disconnection failure.
 */
void MediaDataConnection::OnAbilityDisconnectDone(const AppExecFwk::ElementName &element, int resultCode)
{
    HILOG_INFO("%{public}s called begin", __func__);
    mediaDataProxy_ = nullptr;
    isConnected_.store(false);
    HILOG_INFO("%{public}s called end", __func__);
}

/**
 * @brief connect remote ability of MediaDataExtAbility.
 */
void MediaDataConnection::ConnectMediaDataExtAbility(const AAFwk::Want &want, const sptr<IRemoteObject> &token)
{
    HILOG_INFO("%{public}s called begin", __func__);
    ErrCode ret = AAFwk::AbilityManagerClient::GetInstance()->ConnectAbility(want, this, token);
    HILOG_INFO("%{public}s called end, ret=%{public}d", __func__, ret);
}

/**
 * @brief disconnect remote ability of MediaDataExtAbility.
 */
void MediaDataConnection::DisconnectMediaDataExtAbility()
{
    HILOG_INFO("%{public}s called begin", __func__);
    mediaDataProxy_ = nullptr;
    isConnected_.store(false);
    ErrCode ret = AAFwk::AbilityManagerClient::GetInstance()->DisconnectAbility(this);
    HILOG_INFO("%{public}s called end, ret=%{public}d", __func__, ret);
}

/**
 * @brief check whether connected to remote extension ability.
 *
 * @return bool true if connected, otherwise false.
 */
bool MediaDataConnection::IsExtAbilityConnected()
{
    return isConnected_.load();
}

sptr<IMediaData> MediaDataConnection::GetMediaDataProxy()
{
    return mediaDataProxy_;
}
}  // namespace AppExecFwk
}  // namespace OHOS
