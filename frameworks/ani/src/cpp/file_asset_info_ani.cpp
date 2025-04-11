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
#include "medialibrary_ani_log.h"
#include "medialibrary_ani_utils.h"
#include "media_library_enum_ani.h"
#include "media_column.h"

namespace OHOS {
namespace Media {
ani_object FileAssetInfo::ToFileAssetInfoObject(ani_env *env, std::unique_ptr<FileAsset> fileAsset)
{
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
    CHECK_STATUS_RET(SetFileId(env, cls, object, (double)fileAsset->GetId()), "SetFileId failed");
    CHECK_STATUS_RET(SetUri(env, cls, object, fileAsset->GetUri()), "SetUri failed");
    CHECK_STATUS_RET(SetMediaType(env, cls, object, fileAsset->GetMediaType()), "SetMediaType failed");
    CHECK_STATUS_RET(SetDisplayName(env, cls, object, fileAsset->GetDisplayName()), "SetDisplayName failed");
    CHECK_STATUS_RET(SetSize(env, cls, object, (double)fileAsset->GetSize()), "SetSize failed");
    CHECK_STATUS_RET(SetDateAdded(env, cls, object, (double)fileAsset->GetDateAdded()), "SetDateAdded failed");
    CHECK_STATUS_RET(SetDateModified(env, cls, object, (double)fileAsset->GetDateModified()), "SetDateModified failed");
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
    ani_method fileIdSetter {};
    CHECK_STATUS_RET(env->Class_FindMethod(cls, "<set>file_id", nullptr, &fileIdSetter), "No <set>file_id");
    CHECK_STATUS_RET(env->Object_CallMethod_Void(object, fileIdSetter, fileId), "<set>file_id fail");
    return ANI_OK;
}

ani_status FileAssetInfo::SetUri(ani_env *env, ani_class cls, ani_object object, const std::string &uri)
{
    ani_method uriSetter {};
    CHECK_STATUS_RET(env->Class_FindMethod(cls, "<set>uri", nullptr, &uriSetter), "No <set>uri");
    ani_string uriObj {};
    CHECK_STATUS_RET(MediaLibraryAniUtils::ToAniString(env, uri, uriObj), "ToAniString uri fail");
    CHECK_STATUS_RET(env->Object_CallMethod_Void(object, uriSetter, uriObj), "<set>uri fail");
    return ANI_OK;
}

ani_status FileAssetInfo::SetMediaType(ani_env *env, ani_class cls, ani_object object, MediaType mediaType)
{
    ani_method mediaTypeSetter {};
    CHECK_STATUS_RET(env->Class_FindMethod(cls, "<set>media_type", nullptr, &mediaTypeSetter), "No <set>media_type");
    ani_enum_item mediaTypeObj = 0;
    CHECK_STATUS_RET(MediaLibraryEnumAni::ToAniEnum(env, mediaType, mediaTypeObj), "Get mediaType index fail");
    CHECK_STATUS_RET(env->Object_CallMethod_Void(object, mediaTypeSetter, mediaTypeObj), "<set>media_type fail");
    return ANI_OK;
}

ani_status FileAssetInfo::SetDisplayName(ani_env *env, ani_class cls, ani_object object, const std::string &displayName)
{
    ani_method displayNameSetter {};
    CHECK_STATUS_RET(env->Class_FindMethod(cls, "<set>display_name", nullptr, &displayNameSetter),
        "No <set>display_name");
    ani_string displayNameObj {};
    CHECK_STATUS_RET(MediaLibraryAniUtils::ToAniString(env, displayName, displayNameObj), "ToAniString fail");
    CHECK_STATUS_RET(env->Object_CallMethod_Void(object, displayNameSetter, displayNameObj), "<set>displayName fail");
    return ANI_OK;
}

ani_status FileAssetInfo::SetSize(ani_env *env, ani_class cls, ani_object object, double size)
{
    ani_method doubleSetter {};
    CHECK_STATUS_RET(env->Class_FindMethod(cls, "<set>size", nullptr, &doubleSetter), "No doubleSetter");
    CHECK_STATUS_RET(env->Object_CallMethod_Void(object, doubleSetter, size), "doubleSetter fail");
    return ANI_OK;
}

ani_status FileAssetInfo::SetDateAdded(ani_env *env, ani_class cls, ani_object object, double dateAdded)
{
    ani_method doubleSetter {};
    CHECK_STATUS_RET(env->Class_FindMethod(cls, "<set>date_added", nullptr, &doubleSetter), "No doubleSetter");
    CHECK_STATUS_RET(env->Object_CallMethod_Void(object, doubleSetter, dateAdded), "doubleSetter fail");
    return ANI_OK;
}

ani_status FileAssetInfo::SetDateModified(ani_env *env, ani_class cls, ani_object object, double dateModified)
{
    ani_method doubleSetter {};
    CHECK_STATUS_RET(env->Class_FindMethod(cls, "<set>date_modified", nullptr, &doubleSetter), "No doubleSetter");
    CHECK_STATUS_RET(env->Object_CallMethod_Void(object, doubleSetter, dateModified), "doubleSetter fail");
    return ANI_OK;
}

ani_status FileAssetInfo::SetDuration(ani_env *env, ani_class cls, ani_object object, double duration)
{
    ani_method doubleSetter {};
    CHECK_STATUS_RET(env->Class_FindMethod(cls, "<set>duration", nullptr, &doubleSetter), "No doubleSetter");
    CHECK_STATUS_RET(env->Object_CallMethod_Void(object, doubleSetter, duration), "doubleSetter fail");
    return ANI_OK;
}

ani_status FileAssetInfo::SetWidth(ani_env *env, ani_class cls, ani_object object, double width)
{
    ani_method doubleSetter {};
    CHECK_STATUS_RET(env->Class_FindMethod(cls, "<set>width", nullptr, &doubleSetter), "No doubleSetter");
    CHECK_STATUS_RET(env->Object_CallMethod_Void(object, doubleSetter, width), "doubleSetter fail");
    return ANI_OK;
}

ani_status FileAssetInfo::SetHeight(ani_env *env, ani_class cls, ani_object object, double height)
{
    ani_method doubleSetter {};
    CHECK_STATUS_RET(env->Class_FindMethod(cls, "<set>height", nullptr, &doubleSetter), "No doubleSetter");
    CHECK_STATUS_RET(env->Object_CallMethod_Void(object, doubleSetter, height), "doubleSetter fail");
    return ANI_OK;
}

ani_status FileAssetInfo::SetDateTaken(ani_env *env, ani_class cls, ani_object object, double dateTaken)
{
    ani_method doubleSetter {};
    CHECK_STATUS_RET(env->Class_FindMethod(cls, "<set>date_taken", nullptr, &doubleSetter), "No doubleSetter");
    CHECK_STATUS_RET(env->Object_CallMethod_Void(object, doubleSetter, dateTaken), "doubleSetter fail");
    return ANI_OK;
}

ani_status FileAssetInfo::SetOrientation(ani_env *env, ani_class cls, ani_object object, double orientation)
{
    ani_method doubleSetter {};
    CHECK_STATUS_RET(env->Class_FindMethod(cls, "<set>orientation", nullptr, &doubleSetter), "No doubleSetter");
    CHECK_STATUS_RET(env->Object_CallMethod_Void(object, doubleSetter, orientation), "doubleSetter fail");
    return ANI_OK;
}

ani_status FileAssetInfo::SetIsFavorite(ani_env *env, ani_class cls, ani_object object, bool isFavorite)
{
    ani_method boolSetter {};
    CHECK_STATUS_RET(env->Class_FindMethod(cls, "<set>is_favorite", nullptr, &boolSetter), "No boolSetter");
    CHECK_STATUS_RET(env->Object_CallMethod_Void(object, boolSetter, isFavorite), "boolSetter fail");
    return ANI_OK;
}

ani_status FileAssetInfo::SetTitle(ani_env *env, ani_class cls, ani_object object, const std::string &title)
{
    ani_method strSetter {};
    CHECK_STATUS_RET(env->Class_FindMethod(cls, "<set>title", nullptr, &strSetter), "No strSetter");
    ani_string strObj {};
    CHECK_STATUS_RET(MediaLibraryAniUtils::ToAniString(env, title, strObj), "ToAniString fail");
    CHECK_STATUS_RET(env->Object_CallMethod_Void(object, strSetter, strObj), "strSetter fail");
    return ANI_OK;
}

ani_status FileAssetInfo::SetPosition(ani_env *env, ani_class cls, ani_object object, PhotoPositionType position)
{
    ani_method positionSetter {};
    CHECK_STATUS_RET(env->Class_FindMethod(cls, "<set>position", nullptr, &positionSetter), "No <set>position");
    ani_enum_item positionObj = 0;
    CHECK_STATUS_RET(MediaLibraryEnumAni::ToAniEnum(env, position, positionObj), "Get position object fail");
    CHECK_STATUS_RET(env->Object_CallMethod_Void(object, positionSetter, positionObj), "<set>position fail");
    return ANI_OK;
}

ani_status FileAssetInfo::SetDateTrashed(ani_env *env, ani_class cls, ani_object object, double dateTrashed)
{
    ani_method doubleSetter {};
    CHECK_STATUS_RET(env->Class_FindMethod(cls, "<set>date_trashed", nullptr, &doubleSetter), "No doubleSetter");
    CHECK_STATUS_RET(env->Object_CallMethod_Void(object, doubleSetter, dateTrashed), "doubleSetter fail");
    return ANI_OK;
}

ani_status FileAssetInfo::SetHidden(ani_env *env, ani_class cls, ani_object object, bool hidden)
{
    ani_method boolSetter {};
    CHECK_STATUS_RET(env->Class_FindMethod(cls, "<set>hidden", nullptr, &boolSetter), "No boolSetter");
    CHECK_STATUS_RET(env->Object_CallMethod_Void(object, boolSetter, hidden), "boolSetter fail");
    return ANI_OK;
}

ani_status FileAssetInfo::SetUserComment(ani_env *env, ani_class cls, ani_object object, const std::string &userComment)
{
    ani_method strSetter {};
    CHECK_STATUS_RET(env->Class_FindMethod(cls, "<set>user_comment", nullptr, &strSetter), "No strSetter");
    ani_string strObj {};
    CHECK_STATUS_RET(MediaLibraryAniUtils::ToAniString(env, userComment, strObj), "ToAniString fail");
    CHECK_STATUS_RET(env->Object_CallMethod_Void(object, strSetter, strObj), "strSetter fail");
    return ANI_OK;
}

ani_status FileAssetInfo::SetCameraShotKey(ani_env *env, ani_class cls, ani_object object, const std::string &camera)
{
    ani_method strSetter {};
    CHECK_STATUS_RET(env->Class_FindMethod(cls, "<set>camera_shot_key", nullptr, &strSetter), "No strSetter");
    ani_string strObj {};
    CHECK_STATUS_RET(MediaLibraryAniUtils::ToAniString(env, camera, strObj), "ToAniString fail");
    CHECK_STATUS_RET(env->Object_CallMethod_Void(object, strSetter, strObj), "strSetter fail");
    return ANI_OK;
}

ani_status FileAssetInfo::SetDateYear(ani_env *env, ani_class cls, ani_object object, const std::string &dateYear)
{
    ani_method strSetter {};
    CHECK_STATUS_RET(env->Class_FindMethod(cls, "<set>date_year", nullptr, &strSetter), "No strSetter");
    ani_string strObj {};
    CHECK_STATUS_RET(MediaLibraryAniUtils::ToAniString(env, dateYear, strObj), "ToAniString fail");
    CHECK_STATUS_RET(env->Object_CallMethod_Void(object, strSetter, strObj), "strSetter fail");
    return ANI_OK;
}

ani_status FileAssetInfo::SetDateMonth(ani_env *env, ani_class cls, ani_object object, const std::string &dateMonth)
{
    ani_method strSetter {};
    CHECK_STATUS_RET(env->Class_FindMethod(cls, "<set>date_month", nullptr, &strSetter), "No strSetter");
    ani_string strObj {};
    CHECK_STATUS_RET(MediaLibraryAniUtils::ToAniString(env, dateMonth, strObj), "ToAniString fail");
    CHECK_STATUS_RET(env->Object_CallMethod_Void(object, strSetter, strObj), "strSetter fail");
    return ANI_OK;
}

ani_status FileAssetInfo::SetDateDay(ani_env *env, ani_class cls, ani_object object, const std::string &dateDay)
{
    ani_method strSetter {};
    CHECK_STATUS_RET(env->Class_FindMethod(cls, "<set>date_day", nullptr, &strSetter), "No strSetter");
    ani_string strObj {};
    CHECK_STATUS_RET(MediaLibraryAniUtils::ToAniString(env, dateDay, strObj), "ToAniString fail");
    CHECK_STATUS_RET(env->Object_CallMethod_Void(object, strSetter, strObj), "strSetter fail");
    return ANI_OK;
}

ani_status FileAssetInfo::SetPending(ani_env *env, ani_class cls, ani_object object, bool pending)
{
    ani_method boolSetter {};
    CHECK_STATUS_RET(env->Class_FindMethod(cls, "<set>pending", nullptr, &boolSetter), "No boolSetter");
    CHECK_STATUS_RET(env->Object_CallMethod_Void(object, boolSetter, pending), "boolSetter fail");
    return ANI_OK;
}

ani_status FileAssetInfo::SetDateAddedMs(ani_env *env, ani_class cls, ani_object object, double dateAddedMs)
{
    ani_method doubleSetter {};
    CHECK_STATUS_RET(env->Class_FindMethod(cls, "<set>date_added_ms", nullptr, &doubleSetter), "No doubleSetter");
    CHECK_STATUS_RET(env->Object_CallMethod_Void(object, doubleSetter, dateAddedMs), "doubleSetter fail");
    return ANI_OK;
}

ani_status FileAssetInfo::SetDateModifiedMs(ani_env *env, ani_class cls, ani_object object, double dateModifiedMs)
{
    ani_method doubleSetter {};
    CHECK_STATUS_RET(env->Class_FindMethod(cls, "<set>date_modified_ms", nullptr, &doubleSetter), "No doubleSetter");
    CHECK_STATUS_RET(env->Object_CallMethod_Void(object, doubleSetter, dateModifiedMs), "doubleSetter fail");
    return ANI_OK;
}

ani_status FileAssetInfo::SetDateTrashedMs(ani_env *env, ani_class cls, ani_object object, double dateTrashedMs)
{
    ani_method doubleSetter {};
    CHECK_STATUS_RET(env->Class_FindMethod(cls, "<set>date_trashed_ms", nullptr, &doubleSetter), "No doubleSetter");
    CHECK_STATUS_RET(env->Object_CallMethod_Void(object, doubleSetter, dateTrashedMs), "doubleSetter fail");
    return ANI_OK;
}

ani_status FileAssetInfo::SetSubtype(ani_env *env, ani_class cls, ani_object object, PhotoSubType subtype)
{
    ani_method subtypeSetter {};
    CHECK_STATUS_RET(env->Class_FindMethod(cls, "<set>subtype", nullptr, &subtypeSetter), "No <set>subtype");
    ani_enum_item subtypeObj = 0;
    CHECK_STATUS_RET(MediaLibraryEnumAni::ToAniEnum(env, subtype, subtypeObj), "Get subtype object fail");
    CHECK_STATUS_RET(env->Object_CallMethod_Void(object, subtypeSetter, subtypeObj), "<set>subtype fail");
    return ANI_OK;
}
} // namespace Media
} // namespace OHOS