/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_MEDIALIBRARY_TRIGGER_MANAGER_H
#define OHOS_MEDIALIBRARY_TRIGGER_MANAGER_H

#include "medialibrary_trigger.h"

namespace OHOS {
namespace Media {

class MediaLibraryTriggerManager {
public:
    enum class TriggerType {
        INSERT,
        UPDATE,
        DELETE
    };
    static MediaLibraryTriggerManager& GetInstance()
    {
        static MediaLibraryTriggerManager instance;
        return instance;
    }
    MediaLibraryTriggerManager(const MediaLibraryTriggerManager&) = delete;
    MediaLibraryTriggerManager& operator=(const MediaLibraryTriggerManager&) = delete;
    std::shared_ptr<MediaLibraryTriggerBase> GetTrigger(const std::string &table, TriggerType triggerType);
private:
    using GetTriggerFunc = std::function<std::shared_ptr<MediaLibraryTriggerBase>()>;
    using GetTriggerFuncVec = std::vector<GetTriggerFunc>;
    MediaLibraryTriggerManager();
    std::unordered_map<std::string, GetTriggerFuncVec> getTriggersFuncs_;
};
} // namespace Media
} // namespace OHOS
#endif // OHOS_MEDIALIBRARY_TRIGGER_MANAGER_H