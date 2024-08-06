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

#ifndef FRAMEWORKS_SERVICES_CLOUD_SYNC_NOTIFY_HANDLE_INCLUDE_ANALYSYS_HANDLER_H
#define FRAMEWORKS_SERVICES_CLOUD_SYNC_NOTIFY_HANDLE_INCLUDE_ANALYSYS_HANDLER_H

#include <functional>
#include "base_handler.h"
#include "medialibrary_album_operations.h"

namespace OHOS {
namespace Media {

class AnalysisHandler : public BaseHandler {
public:
    AnalysisHandler(std::function<void(bool)> refreshAlbums = nullptr)
        : refreshAlbumsFunc_(refreshAlbums ? refreshAlbums : [](bool){ RefreshAlbums(true); }) {}
    void Handle(const CloudSyncHandleData &handleData) override;


private:
    std::function<void(bool)> refreshAlbumsFunc_;
};
} //namespace Media
} //namespace OHOS

#endif //FRAMEWORKS_SERVICES_CLOUD_SYNC_NOTIFY_HANDLE_INCLUDE_ANALYSYS_HANDLER_H
