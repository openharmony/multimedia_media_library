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

#ifndef OHOS_MEDIALIBRARY_CLONE_TO_ALBUM_CALLBACK_STUB_H
#define OHOS_MEDIALIBRARY_CLONE_TO_ALBUM_CALLBACK_STUB_H

#include <string>
#include <vector>
#include <map>

#include "iremote_stub.h"
#include "iclone_to_album_callback.h"

namespace OHOS {
namespace Media {

class CloneToAlbumCallbackStub : public IRemoteStub<ICloneToAlbumCallback> {
public:
    CloneToAlbumCallbackStub() = default;
    virtual ~CloneToAlbumCallbackStub() = default;

    int32_t OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
        MessageOption &option) override;

    int32_t OnProgress(uint64_t processedSize, uint64_t totalSize,
        uint32_t processedCount, uint32_t totalCount) override = 0;
    int32_t OnComplete(int32_t errorCode, const std::vector<std::string> &successUris,
        std::shared_ptr<DataShare::DataShareResultSet> &resultSet) override = 0;

    using RequestHandle = int32_t (CloneToAlbumCallbackStub::*)(MessageParcel &, MessageParcel &);
    const std::map<uint32_t, RequestHandle> HANDLERS = {
        {
            static_cast<uint32_t>(CloneToAlbumCallbackInterfaceCode::CLONE_TO_ALBUM_ON_PROGRESS),
            &CloneToAlbumCallbackStub::OnProgress
        },
        {
            static_cast<uint32_t>(CloneToAlbumCallbackInterfaceCode::CLONE_TO_ALBUM_ON_COMPLETE),
            &CloneToAlbumCallbackStub::OnComplete
        },
    };

    int32_t OnProgress(MessageParcel &data, MessageParcel &reply);
    int32_t OnComplete(MessageParcel &data, MessageParcel &reply);
};

} // namespace Media
} // namespace OHOS

#endif // OHOS_MEDIALIBRARY_CLONE_TO_ALBUM_CALLBACK_STUB_H
