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

#ifndef FRAMEWORKS_SERVICES_CLOUD_SYNC_NOTIFY_HANDLE_INCLUDE_NOTIFY_RESPONSIBILITY_CHAIN_FACTORY_H
#define FRAMEWORKS_SERVICES_CLOUD_SYNC_NOTIFY_HANDLE_INCLUDE_NOTIFY_RESPONSIBILITY_CHAIN_FACTORY_H

#include <unordered_map>
#include <list>

#include "base_handler.h"

namespace OHOS {
namespace Media {

enum ChainType {
    TRANSPARENT = 0,
    PHOTODELETE,
    ALBUM_DELETE,
    GALLERY_PHOTO_DELETE
};

class NotifyResponsibilityChainFactory {
public:
    NotifyResponsibilityChainFactory();
    ~NotifyResponsibilityChainFactory();

    static std::unordered_map<ChainType, std::list<std::shared_ptr<BaseHandler>>> handlerMap_;
    static std::shared_ptr<BaseHandler> CreateChain(const ChainType &type);
};
} //namespace Media
} //namespace OHOS

#endif //FRAMEWORKS_SERVICES_CLOUD_SYNC_NOTIFY_HANDLE_INCLUDE_NOTIFY_RESPONSIBILITY_CHAIN_FACTORY_H
