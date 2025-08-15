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

#include "file_asset_info_ani.h"

#include "ani_class_name.h"
#include "medialibrary_ani_utils.h"
#include "media_library_enum_ani.h"
#include "media_column.h"
#include <ani_signature_builder.h>

namespace OHOS {
namespace Media {
using namespace arkts::ani_signature;

ani_object FileAssetInfo::ToFileAssetInfoObject(ani_env *env, std::unique_ptr<FileAsset> fileAsset)
{
    CHECK_COND_RET(env != nullptr, nullptr, "env is nullptr");
    ani_class cls;
    if (ANI_OK != env->FindClass(PAH_ANI_CLASS_FILE_ASSET_INFO.c_str(), &cls)) {
        ANI_ERR_LOG("Failed to find class: %{public}s", PAH_ANI_CLASS_FILE_ASSET_INFO.c_str());
        return nullptr;
    }

    ani_method ctor;
    if (ANI_OK != env->Class_FindMethod(cls, "<ctor>", nullptr, &ctor)) {
        ANI_ERR_LOG("Failed to find method: %{public}s", "ctor");
        return nullptr;
    }

    ani_object fileAssetObj = nullptr;
    if (ANI_OK != env->Object_New(cls, ctor, &fileAssetObj)) {
        ANI_ERR_LOG("New FileAsset Fail");
        return nullptr;
    }
    if (ANI_OK != BindFileAssetInfoAttributes(env, cls, fileAssetObj, std::move(fileAsset))) {
        ANI_ERR_LOG("BindFileAssetInfoAttributes failed");
        return nullptr;
    }
    return fileAssetObj;
}

ani_status FileAssetInfo::BindFileAssetInfoAttributes(ani_env *env, ani_class cls, ani_object object,
    std::unique_ptr<FileAsset> fileAsset)
{
    CHECK_COND_RET(env != nullptr, ANI_ERROR, "env is nullptr");
    CHECK_COND_RET(fileAsset != nullptr, ANI_ERROR, "fileAsset is nullptr");
    CHECK_STATUS_RET(SetFileId(env, cls, object, (double)fileAsset->GetId()), "SetFileId failed");
    CHECK_STATUS_RET(SetUri(env, cls, object, fileAsset->GetUri()), "SetUri failed");
    CHECK_STATUS_RET(SetMediaType(env, cls, object, fileAsset->GetMediaType()), "SetMediaType failed");
    CHECK_STATUS_RET(SetDisplayName(env, cls, object, fileAsset->GetDisplayName()), "SetDisplayName failed");
    CHECK_STATUS_RET(SetSize(env, cls, object, (double)fileAsset->GetSize()), "SetSize failed");
    CHECK_STATUS_RET(SetDateAdded(env, cls, object, (double)fileAsset->GetDateAdded()), "SetDateAdded failed");
    CHECK_STATUS_RET(SetDateModified(env, cls, object, (double)fileAsset->GetDateModified()),
        "SetDateModified failed");
    CHECK_STATUS_RET(SetDuration(env, cls, object, (double)fileAsset->GetDuration()), "SetDuration failed");
    CHECK_STATUS_RET(SetWidth(env, cls, object, (double)fileAsset->GetWidth()), "SetWidth failed");
    CHECK_STATUS_RET(SetHeight(env, cls, object, (double)fileAsset->GetHeight()), "SetHeight failed");
    CHECK_STATUS_RET(SetDateTaken(env, cls, object, (double)fileAsset->GetDateTaken()), "SetDateTaken failed");
    CHECK_STATUS_RET(SetOrientation(env, cls, object, (double)fileAsset->GetOrientation()), "SetOrientation failed");
    CHECK_STATUS_RET(SetIsFavorite(env, cls, object, fileAsset->IsFavorite()), "SetIsFavorite failed");
    CHECK_STATUS_RET(SetTitle(env, cls, object, fileAsset->GetTitle()), "SetTitle failed");
    CHECK_STATUS_RET(SetPosition(env, cls, object, (PhotoPositionType)fileAsset->GetPosition()), "SetPosition failed");
    CHECK_STATUS_RET(SetDateTrashed(env, cls, object, (double)fileAsset->GetDateTrashed()), "SetDateTrashed failed");
    CHECK_STATUS_RET(SetHidden(env, cls, object, fileAsset->IsHidden()), "SetHidden failed");
    CHECK_STATUS_RET(SetUserComment(env, cls, object, fileAsset->GetUserComment()), "SetUserComment failed");
    CHECK_STATUS_RET(SetCameraShotKey(env, cls, object, fileAsset->GetCameraShotKey()), "SetCameraShotKey failed");
    CHECK_STATUS_RET(SetDateYear(env, cls, object, fileAsset->GetStrMember(PhotoColumn::PHOTO_DATE_YEAR)),
        "SetDateYear failed");
    CHECK_STATUS_RET(SetDateMonth(env, cls, object, fileAsset->GetStrMember(PhotoColumn::PHOTO_DATE_MONTH)),
        "SetDateMonth failed");
    CHECK_STATUS_RET(SetDateDay(env, cls, object, fileAsset->GetStrMember(PhotoColumn::PHOTO_DATE_DAY)),
        "SetDateDay failed");
    CHECK_STATUS_RET(SetPending(env, cls, object, fileAsset->GetTimePending()), "SetPending failed");
    CHECK_STATUS_RET(SetDateAddedMs(env, cls, object, (double)fileAsset->GetDateAdded()), "SetDateAddedMs failed");
    CHECK_STATUS_RET(SetDateModifiedMs(env, cls, object, (double)fileAsset->GetDateModified()),
        "SetDateModifiedMs failed");
    CHECK_STATUS_RET(SetDateTrashedMs(env, cls, object, (double)fileAsset->GetDateTrashed()),
        "SetDateTrashedMs failed");
    CHECK_STATUS_RET(SetSubtype(env, cls, object, (PhotoSubType)fileAsset->GetPhotoSubType()), "SetSubtype failed");
    return ANI_OK;
}

ani_status FileAssetInfo::SetFileId(ani_env *env, ani_class cls, ani_object object, double fileId)
{
    CHECK_COND_RET(env != nullptr, ANI_ERROR, "env is nullptr");
    ani_method fileIdSetter {};
    std::string fileIdSetterName = Builder::BuildSetterName("file_id");
    CHECK_STATUS_RET(env->Class_FindMethod(cls, fileIdSetterName.c_str(), nullptr, &fileIdSetter),
        "No %{public}s", fileIdSetterName.c_str());
    CHECK_STATUS_RET(env->Object_CallMethod_Void(object, fileIdSetter, fileId),
        "%{public}s fail", fileIdSetterName.c_str());
    return ANI_OK;
}

ani_status FileAssetInfo::SetUri(ani_env *env, ani_class cls, ani_object object, const std::string &uri)
{
    CHECK_COND_RET(env != nullptr, ANI_ERROR, "env is nullptr");
    ani_method uriSetter {};
    std::string uriSetterName = Builder::BuildSetterName("uri");
    CHECK_STATUS_RET(env->Class_FindMethod(cls, uriSetterName.c_str(), nullptr, &uriSetter),
        "No %{public}s", uriSetterName.c_str());
    ani_string uriObj {};
    CHECK_STATUS_RET(MediaLibraryAniUtils::ToAniString(env, uri, uriObj), "ToAniString uri fail");
    CHECK_STATUS_RET(env->Object_CallMethod_Void(object, uriSetter, uriObj), "%{public}s fail", uriSetterName.c_str());
    return ANI_OK;
}

ani_status FileAssetInfo::SetMediaType(ani_env *env, ani_class cls, ani_object object, MediaType mediaType)
{
    CHECK_COND_RET(env != nullptr, ANI_ERROR, "env is nullptr");
    ani_method mediaTypeSetter {};
    std::string mediaTypeSetterName = Builder::BuildSetterName("media_type");
    CHECK_STATUS_RET(env->Class_FindMethod(cls, mediaTypeSetterName.c_str(), nullptr, &mediaTypeSetter),
        "No %{public}s", mediaTypeSetterName.c_str());
    ani_enum_item mediaTypeObj = 0;
    CHECK_STATUS_RET(MediaLibraryEnumAni::ToAniEnum(env, mediaType, mediaTypeObj), "Get mediaType index fail");
    CHECK_STATUS_RET(env->Object_CallMethod_Void(object, mediaTypeSetter, mediaTypeObj),
        "%{public}s fail", mediaTypeSetterName.c_str());
    return ANI_OK;
}

ani_status FileAssetInfo::SetDisplayName(ani_env *env, ani_class cls, ani_object object, const std::string &displayName)
{
    CHECK_COND_RET(env != nullptr, ANI_ERROR, "env is nullptr");
    ani_method displayNameSetter {};
    std::string displayNameSetterName = Builder::BuildSetterName("display_name");
    CHECK_STATUS_RET(env->Class_FindMethod(cls, displayNameSetterName.c_str(), nullptr, &displayNameSetter),
        "No %{public}s", displayNameSetterName.c_str());
    ani_string displayNameObj {};
    CHECK_STATUS_RET(MediaLibraryAniUtils::ToAniString(env, displayName, displayNameObj), "ToAniString fail");
    CHECK_STATUS_RET(env->Object_CallMethod_Void(object, displayNameSetter, displayNameObj),
        "%{public}s fail", displayNameSetterName.c_str());
    return ANI_OK;
}

ani_status FileAssetInfo::SetSize(ani_env *env, ani_class cls, ani_object object, double size)
{
    CHECK_COND_RET(env != nullptr, ANI_ERROR, "env is nullptr");
    ani_method doubleSetter {};
    CHECK_STATUS_RET(env->Class_FindMethod(cls, Builder::BuildSetterName("size").c_str(), nullptr, &doubleSetter),
        "No doubleSetter");
    CHECK_STATUS_RET(env->Object_CallMethod_Void(object, doubleSetter, size), "doubleSetter fail");
    return ANI_OK;
}

ani_status FileAssetInfo::SetDateAdded(ani_env *env, ani_class cls, ani_object object, double dateAdded)
{
    CHECK_COND_RET(env != nullptr, ANI_ERROR, "env is nullptr");
    ani_method doubleSetter {};
    CHECK_STATUS_RET(env->Class_FindMethod(cls, Builder::BuildSetterName("date_added").c_str(), nullptr, &doubleSetter),
        "No doubleSetter");
    CHECK_STATUS_RET(env->Object_CallMethod_Void(object, doubleSetter, dateAdded), "doubleSetter fail");
    return ANI_OK;
}

ani_status FileAssetInfo::SetDateModified(ani_env *env, ani_class cls, ani_object object, double dateModified)
{
    CHECK_COND_RET(env != nullptr, ANI_ERROR, "env is nullptr");
    ani_method doubleSetter {};
    CHECK_STATUS_RET(env->Class_FindMethod(cls, Builder::BuildSetterName("date_modified").c_str(), nullptr,
        &doubleSetter), "No doubleSetter");
    CHECK_STATUS_RET(env->Object_CallMethod_Void(object, doubleSetter, dateModified), "doubleSetter fail");
    return ANI_OK;
}

ani_status FileAssetInfo::SetDuration(ani_env *env, ani_class cls, ani_object object, double duration)
{
    CHECK_COND_RET(env != nullptr, ANI_ERROR, "env is nullptr");
    ani_method doubleSetter {};
    CHECK_STATUS_RET(env->Class_FindMethod(cls, Builder::BuildSetterName("duration").c_str(), nullptr, &doubleSetter),
        "No doubleSetter");
    CHECK_STATUS_RET(env->Object_CallMethod_Void(object, doubleSetter, duration), "doubleSetter fail");
    return ANI_OK;
}

ani_status FileAssetInfo::SetWidth(ani_env *env, ani_class cls, ani_object object, double width)
{
    CHECK_COND_RET(env != nullptr, ANI_ERROR, "env is nullptr");
    ani_method doubleSetter {};
    CHECK_STATUS_RET(env->Class_FindMethod(cls, Builder::BuildSetterName("width").c_str(), nullptr, &doubleSetter),
        "No doubleSetter");
    CHECK_STATUS_RET(env->Object_CallMethod_Void(object, doubleSetter, width), "doubleSetter fail");
    return ANI_OK;
}

ani_status FileAssetInfo::SetHeight(ani_env *env, ani_class cls, ani_object object, double height)
{
    CHECK_COND_RET(env != nullptr, ANI_ERROR, "env is nullptr");
    ani_method doubleSetter {};
    CHECK_STATUS_RET(env->Class_FindMethod(cls, Builder::BuildSetterName("height").c_str(), nullptr, &doubleSetter),
        "No doubleSetter");
    CHECK_STATUS_RET(env->Object_CallMethod_Void(object, doubleSetter, height), "doubleSetter fail");
    return ANI_OK;
}

ani_status FileAssetInfo::SetDateTaken(ani_env *env, ani_class cls, ani_object object, double dateTaken)
{
    CHECK_COND_RET(env != nullptr, ANI_ERROR, "env is nullptr");
    ani_method doubleSetter {};
    CHECK_STATUS_RET(env->Class_FindMethod(cls, Builder::BuildSetterName("date_taken").c_str(), nullptr, &doubleSetter),
        "No doubleSetter");
    CHECK_STATUS_RET(env->Object_CallMethod_Void(object, doubleSetter, dateTaken), "doubleSetter fail");
    return ANI_OK;
}

ani_status FileAssetInfo::SetOrientation(ani_env *env, ani_class cls, ani_object object, double orientation)
{
    CHECK_COND_RET(env != nullptr, ANI_ERROR, "env is nullptr");
    ani_method doubleSetter {};
    CHECK_STATUS_RET(env->Class_FindMethod(cls, Builder::BuildSetterName("orientation").c_str(), nullptr,
        &doubleSetter), "No doubleSetter");
    CHECK_STATUS_RET(env->Object_CallMethod_Void(object, doubleSetter, orientation), "doubleSetter fail");
    return ANI_OK;
}

ani_status FileAssetInfo::SetIsFavorite(ani_env *env, ani_class cls, ani_object object, bool isFavorite)
{
    CHECK_COND_RET(env != nullptr, ANI_ERROR, "env is nullptr");
    ani_method boolSetter {};
    CHECK_STATUS_RET(env->Class_FindMethod(cls, Builder::BuildSetterName("is_favorite").c_str(), nullptr, &boolSetter),
        "No boolSetter");
    CHECK_STATUS_RET(env->Object_CallMethod_Void(object, boolSetter, isFavorite), "boolSetter fail");
    return ANI_OK;
}

ani_status FileAssetInfo::SetTitle(ani_env *env, ani_class cls, ani_object object, const std::string &title)
{
    CHECK_COND_RET(env != nullptr, ANI_ERROR, "env is nullptr");
    ani_method strSetter {};
    CHECK_STATUS_RET(env->Class_FindMethod(cls, Builder::BuildSetterName("title").c_str(), nullptr, &strSetter),
        "No strSetter");
    ani_string strObj {};
    CHECK_STATUS_RET(MediaLibraryAniUtils::ToAniString(env, title, strObj), "ToAniString fail");
    CHECK_STATUS_RET(env->Object_CallMethod_Void(object, strSetter, strObj), "strSetter fail");
    return ANI_OK;
}

ani_status FileAssetInfo::SetPosition(ani_env *env, ani_class cls, ani_object object, PhotoPositionType position)
{
    CHECK_COND_RET(env != nullptr, ANI_ERROR, "env is nullptr");
    ani_method positionSetter {};
    std::string positionSetterName = Builder::BuildSetterName("position");
    CHECK_STATUS_RET(env->Class_FindMethod(cls, positionSetterName.c_str(), nullptr, &positionSetter),
        "No %{public}s", positionSetterName.c_str());
    ani_enum_item positionObj = 0;
    CHECK_STATUS_RET(MediaLibraryEnumAni::ToAniEnum(env, position, positionObj), "Get position object fail");
    CHECK_STATUS_RET(env->Object_CallMethod_Void(object, positionSetter, positionObj),
        "%{public}s fail", positionSetterName.c_str());
    return ANI_OK;
}

ani_status FileAssetInfo::SetDateTrashed(ani_env *env, ani_class cls, ani_object object, double dateTrashed)
{
    CHECK_COND_RET(env != nullptr, ANI_ERROR, "env is nullptr");
    ani_method doubleSetter {};
    CHECK_STATUS_RET(env->Class_FindMethod(cls, Builder::BuildSetterName("date_trashed").c_str(), nullptr,
        &doubleSetter), "No doubleSetter");
    CHECK_STATUS_RET(env->Object_CallMethod_Void(object, doubleSetter, dateTrashed), "doubleSetter fail");
    return ANI_OK;
}

ani_status FileAssetInfo::SetHidden(ani_env *env, ani_class cls, ani_object object, bool hidden)
{
    CHECK_COND_RET(env != nullptr, ANI_ERROR, "env is nullptr");
    ani_method boolSetter {};
    CHECK_STATUS_RET(env->Class_FindMethod(cls, Builder::BuildSetterName("hidden").c_str(), nullptr, &boolSetter),
        "No boolSetter");
    CHECK_STATUS_RET(env->Object_CallMethod_Void(object, boolSetter, hidden), "boolSetter fail");
    return ANI_OK;
}

ani_status FileAssetInfo::SetUserComment(ani_env *env, ani_class cls, ani_object object, const std::string &userComment)
{
    CHECK_COND_RET(env != nullptr, ANI_ERROR, "env is nullptr");
    ani_method strSetter {};
    CHECK_STATUS_RET(env->Class_FindMethod(cls, Builder::BuildSetterName("user_comment").c_str(), nullptr, &strSetter),
        "No strSetter");
    ani_string strObj {};
    CHECK_STATUS_RET(MediaLibraryAniUtils::ToAniString(env, userComment, strObj), "ToAniString fail");
    CHECK_STATUS_RET(env->Object_CallMethod_Void(object, strSetter, strObj), "strSetter fail");
    return ANI_OK;
}

ani_status FileAssetInfo::SetCameraShotKey(ani_env *env, ani_class cls, ani_object object, const std::string &camera)
{
    CHECK_COND_RET(env != nullptr, ANI_ERROR, "env is nullptr");
    ani_method strSetter {};
    CHECK_STATUS_RET(env->Class_FindMethod(cls, Builder::BuildSetterName("camera_shot_key").c_str(), nullptr,
        &strSetter), "No strSetter");
    ani_string strObj {};
    CHECK_STATUS_RET(MediaLibraryAniUtils::ToAniString(env, camera, strObj), "ToAniString fail");
    CHECK_STATUS_RET(env->Object_CallMethod_Void(object, strSetter, strObj), "strSetter fail");
    return ANI_OK;
}

ani_status FileAssetInfo::SetDateYear(ani_env *env, ani_class cls, ani_object object, const std::string &dateYear)
{
    CHECK_COND_RET(env != nullptr, ANI_ERROR, "env is nullptr");
    ani_method strSetter {};
    CHECK_STATUS_RET(env->Class_FindMethod(cls, Builder::BuildSetterName("date_year").c_str(), nullptr, &strSetter),
        "No strSetter");
    ani_string strObj {};
    CHECK_STATUS_RET(MediaLibraryAniUtils::ToAniString(env, dateYear, strObj), "ToAniString fail");
    CHECK_STATUS_RET(env->Object_CallMethod_Void(object, strSetter, strObj), "strSetter fail");
    return ANI_OK;
}

ani_status FileAssetInfo::SetDateMonth(ani_env *env, ani_class cls, ani_object object, const std::string &dateMonth)
{
    CHECK_COND_RET(env != nullptr, ANI_ERROR, "env is nullptr");
    ani_method strSetter {};
    CHECK_STATUS_RET(env->Class_FindMethod(cls, Builder::BuildSetterName("date_month").c_str(), nullptr, &strSetter),
        "No strSetter");
    ani_string strObj {};
    CHECK_STATUS_RET(MediaLibraryAniUtils::ToAniString(env, dateMonth, strObj), "ToAniString fail");
    CHECK_STATUS_RET(env->Object_CallMethod_Void(object, strSetter, strObj), "strSetter fail");
    return ANI_OK;
}

ani_status FileAssetInfo::SetDateDay(ani_env *env, ani_class cls, ani_object object, const std::string &dateDay)
{
    CHECK_COND_RET(env != nullptr, ANI_ERROR, "env is nullptr");
    ani_method strSetter {};
    CHECK_STATUS_RET(env->Class_FindMethod(cls, Builder::BuildSetterName("date_day").c_str(), nullptr, &strSetter),
        "No strSetter");
    ani_string strObj {};
    CHECK_STATUS_RET(MediaLibraryAniUtils::ToAniString(env, dateDay, strObj), "ToAniString fail");
    CHECK_STATUS_RET(env->Object_CallMethod_Void(object, strSetter, strObj), "strSetter fail");
    return ANI_OK;
}

ani_status FileAssetInfo::SetPending(ani_env *env, ani_class cls, ani_object object, bool pending)
{
    CHECK_COND_RET(env != nullptr, ANI_ERROR, "env is nullptr");
    ani_method boolSetter {};
    CHECK_STATUS_RET(env->Class_FindMethod(cls, Builder::BuildSetterName("pending").c_str(), nullptr, &boolSetter),
        "No boolSetter");
    CHECK_STATUS_RET(env->Object_CallMethod_Void(object, boolSetter, pending), "boolSetter fail");
    return ANI_OK;
}

ani_status FileAssetInfo::SetDateAddedMs(ani_env *env, ani_class cls, ani_object object, double dateAddedMs)
{
    CHECK_COND_RET(env != nullptr, ANI_ERROR, "env is nullptr");
    ani_method doubleSetter {};
    CHECK_STATUS_RET(env->Class_FindMethod(cls, Builder::BuildSetterName("date_added_ms").c_str(), nullptr,
        &doubleSetter), "No doubleSetter");
    CHECK_STATUS_RET(env->Object_CallMethod_Void(object, doubleSetter, dateAddedMs), "doubleSetter fail");
    return ANI_OK;
}

ani_status FileAssetInfo::SetDateModifiedMs(ani_env *env, ani_class cls, ani_object object, double dateModifiedMs)
{
    CHECK_COND_RET(env != nullptr, ANI_ERROR, "env is nullptr");
    ani_method doubleSetter {};
    CHECK_STATUS_RET(env->Class_FindMethod(cls, Builder::BuildSetterName("date_modified_ms").c_str(), nullptr,
        &doubleSetter), "No doubleSetter");
    CHECK_STATUS_RET(env->Object_CallMethod_Void(object, doubleSetter, dateModifiedMs), "doubleSetter fail");
    return ANI_OK;
}

ani_status FileAssetInfo::SetDateTrashedMs(ani_env *env, ani_class cls, ani_object object, double dateTrashedMs)
{
    CHECK_COND_RET(env != nullptr, ANI_ERROR, "env is nullptr");
    ani_method doubleSetter {};
    CHECK_STATUS_RET(env->Class_FindMethod(cls, Builder::BuildSetterName("date_trashed_ms").c_str(), nullptr,
        &doubleSetter), "No doubleSetter");
    CHECK_STATUS_RET(env->Object_CallMethod_Void(object, doubleSetter, dateTrashedMs), "doubleSetter fail");
    return ANI_OK;
}

ani_status FileAssetInfo::SetSubtype(ani_env *env, ani_class cls, ani_object object, PhotoSubType subtype)
{
    CHECK_COND_RET(env != nullptr, ANI_ERROR, "env is nullptr");
    ani_method subtypeSetter {};
    std::string subtypeSetterName = Builder::BuildSetterName("subtype");
    CHECK_STATUS_RET(env->Class_FindMethod(cls, subtypeSetterName.c_str(), nullptr, &subtypeSetter),
        "No %{public}s", subtypeSetterName.c_str());
    ani_enum_item subtypeObj = 0;
    CHECK_STATUS_RET(MediaLibraryEnumAni::ToAniEnum(env, subtype, subtypeObj), "Get subtype object fail");
    CHECK_STATUS_RET(env->Object_CallMethod_Void(object, subtypeSetter, subtypeObj),
        "%{public}s fail", subtypeSetterName.c_str());
    return ANI_OK;
}
} // namespace Media
} // namespace OHOS
