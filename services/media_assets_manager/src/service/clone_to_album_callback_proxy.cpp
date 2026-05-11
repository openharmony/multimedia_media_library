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

#include "clone_to_album_callback_proxy.h"
#include "media_log.h"
#include "medialibrary_errno.h"

namespace OHOS {
namespace Media {

CloneToAlbumCallbackProxy::CloneToAlbumCallbackProxy(const sptr<IRemoteObject> &impl)
    : IRemoteProxy<ICloneToAlbumCallback>(impl) {}

int32_t CloneToAlbumCallbackProxy::OnProgress(uint64_t processedSize, uint64_t totalSize,
    uint32_t processedCount, uint32_t totalCount)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        MEDIA_ERR_LOG("Failed to write interface token");
        return E_ERR;
    }

    if (!data.WriteUint64(processedSize) || !data.WriteUint64(totalSize) ||
        !data.WriteUint32(processedCount) || !data.WriteUint32(totalCount)) {
        MEDIA_ERR_LOG("Failed to write progress data");
        return E_ERR;
    }

    auto remote = Remote();
    if (remote == nullptr) {
        MEDIA_ERR_LOG("Remote is nullptr");
        return E_ERR;
    }

    int32_t ret = remote->SendRequest(CLONE_TO_ALBUM_ON_PROGRESS, data, reply, option);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("SendRequest failed, ret=%{public}d", ret);
        return E_ERR;
    }

    return E_OK;
}

int32_t CloneToAlbumCallbackProxy::OnComplete(int32_t errorCode, const std::vector<std::string> &successUris,
    std::shared_ptr<DataShare::DataShareResultSet> &resultSet)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        MEDIA_ERR_LOG("Failed to write interface token");
        return E_ERR;
    }

    if (!data.WriteInt32(errorCode)) {
        MEDIA_ERR_LOG("Failed to write errorCode");
        return E_ERR;
    }

    if (!data.WriteStringVector(successUris)) {
        MEDIA_ERR_LOG("Failed to write successUris");
        return E_ERR;
    }

    DataShare::DataShareResultSet::Marshal(resultSet, data);

    auto remote = Remote();
    if (remote == nullptr) {
        MEDIA_ERR_LOG("Remote is nullptr");
        return E_ERR;
    }

    int32_t ret = remote->SendRequest(CLONE_TO_ALBUM_ON_COMPLETE, data, reply, option);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("SendRequest failed, ret=%{public}d", ret);
        return E_ERR;
    }

    return E_OK;
}

} // namespace Media
} // namespace OHOS
