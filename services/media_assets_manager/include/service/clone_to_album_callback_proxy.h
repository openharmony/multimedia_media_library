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

#ifndef OHOS_MEDIALIBRARY_CLONE_TO_ALBUM_CALLBACK_PROXY_H
#define OHOS_MEDIALIBRARY_CLONE_TO_ALBUM_CALLBACK_PROXY_H

#include <string>
#include <vector>
#include "iremote_proxy.h"
#include "iclone_to_album_callback.h"

namespace OHOS {
namespace Media {

class CloneToAlbumCallbackProxy : public IRemoteProxy<ICloneToAlbumCallback> {
public:
    explicit CloneToAlbumCallbackProxy(const sptr<IRemoteObject> &impl);
    ~CloneToAlbumCallbackProxy() override = default;

    int32_t OnProgress(uint64_t processedSize, uint64_t totalSize,
        uint32_t processedCount, uint32_t totalCount) override;
    int32_t OnComplete(int32_t errorCode, const std::vector<std::string> &successUris,
        std::shared_ptr<DataShare::DataShareResultSet> &resultSet) override;

private:
    static inline BrokerDelegator<CloneToAlbumCallbackProxy> delegator_;
};

} // namespace Media
} // namespace OHOS

#endif // OHOS_MEDIALIBRARY_CLONE_TO_ALBUM_CALLBACK_PROXY_H
