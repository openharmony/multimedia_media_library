/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef MEDIA_CONFIG_INFO_H
#define MEDIA_CONFIG_INFO_H

#include <string>


namespace OHOS {
namespace Media {
// SceneId const
enum class ConfigInfoSceneId {
    CLONE_RESTORE,
};

const std::unordered_map<int, ConfigInfoSceneId> INT_CONFIG_INFO_SCENE_ID_MAP = {
    {static_cast<int>(ConfigInfoSceneId::CLONE_RESTORE), ConfigInfoSceneId::CLONE_RESTORE},
};

class ConfigInfoColumn {
public:
    static const std::string MEDIA_CONFIG_INFO_TABLE_NAME;
    static const std::string MEDIA_CONFIG_INFO_SCENE_ID;
    static const std::string MEDIA_CONFIG_INFO_KEY;
    static const std::string MEDIA_CONFIG_INFO_VALUE;
    static const std::string CREATE_CONFIG_INFO_TABLE;
};

} // namespace Media
} // namespace OHOS
#endif // MEDIA_CONFIG_INFO_H