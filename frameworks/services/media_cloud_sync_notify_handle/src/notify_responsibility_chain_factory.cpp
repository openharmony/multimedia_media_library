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

#include "notify_responsibility_chain_factory.h"

#include "notify_handler.h"
#include "analysis_handler.h"
#include "cloud_album_handler.h"
#include "uri_convert_handler.h"

using namespace std;

namespace OHOS {
namespace Media {

unordered_map<ChainType, list<shared_ptr<BaseHandler>>> NotifyResponsibilityChainFactory::handlerMap_ = {
    {TRANSPARENT, {
        make_shared<UriConvertHandler>(),
        make_shared<NotifyHandler>()
    }},
    {PHOTODELETE, {
        make_shared<AnalysisHandler>(),
        make_shared<UriConvertHandler>(),
        make_shared<NotifyHandler>()
    }},
    {ALBUM_DELETE, {
        make_shared<CloudAlbumHandler>()
    }},
    {GALLERY_PHOTO_DELETE, {
        make_shared<AnalysisHandler>(),
    }},
};

shared_ptr<BaseHandler> NotifyResponsibilityChainFactory::CreateChain(const ChainType &type)
{
    if (handlerMap_.count(type) > 0) {
        list<shared_ptr<BaseHandler>>& handlerList = handlerMap_[type];
        shared_ptr<BaseHandler> preHandler = nullptr;

        for (const auto& handler : handlerList) {
            handler->init();
            if (preHandler != nullptr) {
                preHandler->SetNextHandler(handler);
            }
            preHandler = handler;
        }
        return handlerList.front();
    } else {
        return nullptr;
    }
}
} //namespace Media
} //namespace OHOS
