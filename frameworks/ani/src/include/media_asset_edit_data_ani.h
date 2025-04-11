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

#ifndef FRAMEWORKS_ANI_SRC_INCLUDE_MEDIA_ASSET_EDIT_DATA_ANI_H
#define FRAMEWORKS_ANI_SRC_INCLUDE_MEDIA_ASSET_EDIT_DATA_ANI_H

#include <string>

#include "media_asset_edit_data.h"
#include "ani_error.h"

namespace OHOS {
namespace Media {
class MediaAssetEditDataAni {
public:
    MediaAssetEditDataAni() = default;
    virtual ~MediaAssetEditDataAni() = default;
    static ani_status Init(ani_env *env);
    static ani_status Constructor(ani_env *env, ani_object aniObject, ani_string compatibleFormat,
        ani_string formatVersion);
    static void Destructor(ani_env *env, void* nativeObject, void* finalizeHint);
    static MediaAssetEditDataAni* Unwrap(ani_env *env, ani_object aniObject);

    std::shared_ptr<MediaAssetEditData> GetMediaAssetEditData() const;

private:
    static void CompatibleFormatSetter(ani_env *env, ani_object object, ani_string compatibleFormat);
    static ani_string CompatibleFormatGetter(ani_env *env, ani_object object);
    static void FormatVersionSetter(ani_env *env, ani_object object, ani_string formatVersion);
    static ani_string FormatVersionGetter(ani_env *env, ani_object object);
    static void DataSetter(ani_env *env, ani_object object, ani_string data);
    static ani_string DataGetter(ani_env *env, ani_object object);

    std::string GetCompatibleFormat() const;
    void SetCompatibleFormat(const std::string& compatibleFormat);
    std::string GetFormatVersion() const;
    void SetFormatVersion(const std::string& formatVersion);
    std::string GetData() const;
    void SetData(const std::string& data);

    std::shared_ptr<MediaAssetEditData> editData_ = nullptr;
};
} // namespace Media
} // namespace OHOS

#endif // FRAMEWORKS_ANI_SRC_INCLUDE_MEDIA_ASSET_EDIT_DATA_ANI_H