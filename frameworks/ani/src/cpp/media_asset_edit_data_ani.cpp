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

#include "ani_class_name.h"
#include "media_asset_edit_data_ani.h"
#include "media_file_utils.h"
#include "medialibrary_ani_utils.h"
#include "medialibrary_client_errno.h"
#include "medialibrary_errno.h"
#include "medialibrary_ani_log.h"

using namespace std;

namespace OHOS::Media {
constexpr int32_t EDIT_FORMAT_MAX_LENGTH = 256;

ani_status MediaAssetEditDataAni::Init(ani_env *env)
{
    static const char *className = PAH_ANI_CLASS_MEDIA_ASSETS_EDIT_DATA.c_str();
    ani_class cls;
    CHECK_COND_RET(env != nullptr, ANI_ERROR, "env is null");
    ani_status status = env->FindClass(className, &cls);
    if (status != ANI_OK) {
        ANI_ERR_LOG("Failed to find class: %{public}s", className);
        return status;
    }

    std::array methods = {
        ani_native_function {"nativeConstructor", nullptr, reinterpret_cast<void *>(Constructor)},
        ani_native_function {"compatibleFormatSetter", nullptr, reinterpret_cast<void *>(CompatibleFormatSetter)},
        ani_native_function {"compatibleFormatGetter", nullptr, reinterpret_cast<void *>(CompatibleFormatGetter)},
        ani_native_function {"formatVersionSetter", nullptr, reinterpret_cast<void *>(FormatVersionSetter)},
        ani_native_function {"formatVersionGetter", nullptr, reinterpret_cast<void *>(FormatVersionGetter)},
        ani_native_function {"dataSetter", nullptr, reinterpret_cast<void *>(DataSetter)},
        ani_native_function {"dataGetter", nullptr, reinterpret_cast<void *>(DataGetter)},
    };

    status = env->Class_BindNativeMethods(cls, methods.data(), methods.size());
    if (status != ANI_OK) {
        ANI_ERR_LOG("Failed to bind native methods to: %{public}s", className);
        return status;
    }
    return ANI_OK;
}

ani_status MediaAssetEditDataAni::Constructor(ani_env *env, ani_object aniObject, ani_string compatibleFormat,
    ani_string formatVersion)
{
    CHECK_COND_RET(env != nullptr, ANI_ERROR, "env is null");
    if (!MediaLibraryAniUtils::IsSystemApp()) {
        AniError::ThrowError(env, E_CHECK_SYSTEMAPP_FAIL, "The constructor can be called only by system apps");
        return ANI_ERROR;
    }

    std::string compatibleFormatInner;
    std::string formatVersionInner;
    CHECK_STATUS_RET(MediaLibraryAniUtils::GetParamStringWithLength(env, compatibleFormat,
        EDIT_FORMAT_MAX_LENGTH, compatibleFormatInner), "GetParamStringWithLength failed!");
    CHECK_STATUS_RET(MediaLibraryAniUtils::GetParamStringWithLength(env, formatVersion,
        EDIT_FORMAT_MAX_LENGTH, formatVersionInner), "GetParamStringWithLength failed!");

    shared_ptr<MediaAssetEditData> editData =
        make_shared<MediaAssetEditData>(compatibleFormatInner, formatVersionInner);
    unique_ptr<MediaAssetEditDataAni> obj = make_unique<MediaAssetEditDataAni>();
    CHECK_COND_RET((editData != nullptr && obj != nullptr), ANI_ERROR,
        "MediaAssetEditData ptr and MediaAssetEditDataAni ptr is null");
    obj->editData_ = editData;
    CHECK_STATUS_RET(env->Object_CallMethodByName_Void(
        aniObject, "create", nullptr, reinterpret_cast<ani_long>(obj.get())),
        "Failed to call create method to construct MediaAssetEditDataAni!");
    obj.release();
    return ANI_OK;
}

MediaAssetEditDataAni* MediaAssetEditDataAni::Unwrap(ani_env *env, ani_object aniObject)
{
    CHECK_COND_RET(env != nullptr, nullptr, "env is null");
    ani_long context;
    if (ANI_OK != env->Object_GetFieldByName_Long(aniObject, "nativeHandle", &context)) {
        return nullptr;
    }
    return reinterpret_cast<MediaAssetEditDataAni*>(context);
}

void MediaAssetEditDataAni::Destructor(ani_env *env, void* nativeObject, void* finalizeHint)
{
    auto* assetEditData = reinterpret_cast<MediaAssetEditDataAni*>(nativeObject);
    if (assetEditData != nullptr) {
        delete assetEditData;
        assetEditData = nullptr;
    }
}

void MediaAssetEditDataAni::CompatibleFormatSetter(ani_env *env, ani_object object, ani_string compatibleFormat)
{
    MediaAssetEditDataAni* assetEditData = Unwrap(env, object);
    CHECK_IF_EQUAL(assetEditData != nullptr, "assetEditData is nullptr");
    std::string compatibleFormatInner;
    CHECK_IF_EQUAL(MediaLibraryAniUtils::GetString(env, compatibleFormat, compatibleFormatInner) == ANI_OK,
        "GetString failed");
    assetEditData->SetCompatibleFormat(compatibleFormatInner);
}

ani_string MediaAssetEditDataAni::CompatibleFormatGetter(ani_env *env, ani_object object)
{
    MediaAssetEditDataAni* assetEditData = Unwrap(env, object);
    CHECK_COND_RET(assetEditData != nullptr, nullptr, "assetEditData is nullptr");
    std::string compatibleFormat = assetEditData->GetCompatibleFormat();
    ani_string aniCompatibleFormat;
    CHECK_COND_RET(MediaLibraryAniUtils::ToAniString(env, compatibleFormat, aniCompatibleFormat) == ANI_OK, nullptr,
        "failed to convert to aniString");
    return aniCompatibleFormat;
}

void MediaAssetEditDataAni::FormatVersionSetter(ani_env *env, ani_object object, ani_string formatVersion)
{
    MediaAssetEditDataAni* assetEditData = Unwrap(env, object);
    CHECK_IF_EQUAL(assetEditData != nullptr, "assetEditData is nullptr");
    std::string formatVersionInner;
    CHECK_IF_EQUAL(MediaLibraryAniUtils::GetString(env, formatVersion, formatVersionInner) == ANI_OK,
        "GetString failed");
    assetEditData->SetFormatVersion(formatVersionInner);
}

ani_string MediaAssetEditDataAni::FormatVersionGetter(ani_env *env, ani_object object)
{
    MediaAssetEditDataAni* assetEditData = Unwrap(env, object);
    CHECK_COND_RET(assetEditData != nullptr, nullptr, "assetEditData is nullptr");
    std::string formatVersion = assetEditData->GetFormatVersion();
    ani_string aniFormatVersion;
    CHECK_COND_RET(MediaLibraryAniUtils::ToAniString(env, formatVersion, aniFormatVersion) == ANI_OK, nullptr,
        "failed to convert to aniString");
    return aniFormatVersion;
}

void MediaAssetEditDataAni::DataSetter(ani_env *env, ani_object object, ani_string data)
{
    MediaAssetEditDataAni* assetEditData = Unwrap(env, object);
    CHECK_IF_EQUAL(assetEditData != nullptr, "assetEditData is nullptr");
    std::string dataInner;
    CHECK_IF_EQUAL(MediaLibraryAniUtils::GetString(env, data, dataInner) == ANI_OK, "GetString failed");
    assetEditData->SetData(dataInner);
}

ani_string MediaAssetEditDataAni::DataGetter(ani_env *env, ani_object object)
{
    MediaAssetEditDataAni* assetEditData = Unwrap(env, object);
    CHECK_COND_RET(assetEditData != nullptr, nullptr, "assetEditData is nullptr");
    std::string data = assetEditData->GetData();
    ani_string aniData;
    CHECK_COND_RET(MediaLibraryAniUtils::ToAniString(env, data, aniData) == ANI_OK, nullptr,
        "failed to convert to aniString");
    return aniData;
}

shared_ptr<MediaAssetEditData> MediaAssetEditDataAni::GetMediaAssetEditData() const
{
    return editData_;
}

string MediaAssetEditDataAni::GetCompatibleFormat() const
{
    return editData_->GetCompatibleFormat();
}

void MediaAssetEditDataAni::SetCompatibleFormat(const string& compatibleFormat)
{
    editData_->SetCompatibleFormat(compatibleFormat);
}

string MediaAssetEditDataAni::GetFormatVersion() const
{
    return editData_->GetFormatVersion();
}

void MediaAssetEditDataAni::SetFormatVersion(const string& formatVersion)
{
    editData_->SetFormatVersion(formatVersion);
}

string MediaAssetEditDataAni::GetData() const
{
    return editData_->GetData();
}

void MediaAssetEditDataAni::SetData(const string& data)
{
    editData_->SetData(data);
}
} // namespace OHOS::Media