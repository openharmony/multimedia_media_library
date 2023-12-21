/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#ifndef INTERFACES_KITS_JS_MEDIALIBRARY_INCLUDE_MEDIA_ASSET_EDIT_DATA_NAPI_H
#define INTERFACES_KITS_JS_MEDIALIBRARY_INCLUDE_MEDIA_ASSET_EDIT_DATA_NAPI_H

#include <string>

#include "media_asset_edit_data.h"
#include "napi_error.h"

namespace OHOS {
namespace Media {
#define EXPORT __attribute__ ((visibility ("default")))
class MediaAssetEditDataNapi {
public:
    EXPORT MediaAssetEditDataNapi() = default;
    EXPORT virtual ~MediaAssetEditDataNapi() = default;

    EXPORT static napi_value Init(napi_env env, napi_value exports);
    EXPORT static napi_value CreateMediaAssetEditData(napi_env env, const std::string& compatibleFormat,
        const std::string& formatVersion, const std::string& data);

    std::shared_ptr<MediaAssetEditData> GetMediaAssetEditData() const;

private:
    EXPORT static napi_value Constructor(napi_env env, napi_callback_info info);
    EXPORT static void Destructor(napi_env env, void* nativeObject, void* finalizeHint);

    EXPORT static napi_value JSGetCompatibleFormat(napi_env env, napi_callback_info info);
    EXPORT static napi_value JSGetFormatVersion(napi_env env, napi_callback_info info);
    EXPORT static napi_value JSGetData(napi_env env, napi_callback_info info);
    EXPORT static napi_value JSSetCompatibleFormat(napi_env env, napi_callback_info info);
    EXPORT static napi_value JSSetFormatVersion(napi_env env, napi_callback_info info);
    EXPORT static napi_value JSSetData(napi_env env, napi_callback_info info);

    std::string GetCompatibleFormat() const;
    void SetCompatibleFormat(const std::string& compatibleFormat);
    std::string GetFormatVersion() const;
    void SetFormatVersion(const std::string& formatVersion);
    std::string GetData() const;
    void SetData(const std::string& data);

    static thread_local napi_ref constructor_;
    std::shared_ptr<MediaAssetEditData> editData_ = nullptr;
};
} // namespace Media
} // namespace OHOS

#endif // INTERFACES_KITS_JS_MEDIALIBRARY_INCLUDE_MEDIA_ASSET_EDIT_DATA_NAPI_H