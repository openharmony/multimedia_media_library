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

#ifndef FRAMEWORKS_ANI_SRC_INCLUDE_FILE_ASSET_INFO_ANI_H
#define FRAMEWORKS_ANI_SRC_INCLUDE_FILE_ASSET_INFO_ANI_H

#include <ani.h>
#include <memory>
#include <string>

#include "file_asset.h"
#include "userfile_manager_types.h"

namespace OHOS {
namespace Media {
class FileAssetInfo {
public:
    static ani_object ToFileAssetInfoObject(ani_env *env, std::unique_ptr<FileAsset> fileAsset);
    static ani_status BindFileAssetInfoAttributes(ani_env *env, ani_class cls, ani_object object,
        std::unique_ptr<FileAsset> fileAsset);

    static ani_status SetFileId(ani_env *env, ani_class cls, ani_object object, double fileId);
    static ani_status SetUri(ani_env *env, ani_class cls, ani_object object, const std::string &uri);
    static ani_status SetMediaType(ani_env *env, ani_class cls, ani_object object, MediaType mediaType);
    static ani_status SetDisplayName(ani_env *env, ani_class cls, ani_object object, const std::string &displayName);
    static ani_status SetSize(ani_env *env, ani_class cls, ani_object object, double size);
    static ani_status SetDateAdded(ani_env *env, ani_class cls, ani_object object, double dateAdded);
    static ani_status SetDateModified(ani_env *env, ani_class cls, ani_object object, double dateModified);
    static ani_status SetDuration(ani_env *env, ani_class cls, ani_object object, double duration);
    static ani_status SetWidth(ani_env *env, ani_class cls, ani_object object, double width);
    static ani_status SetHeight(ani_env *env, ani_class cls, ani_object object, double height);
    static ani_status SetDateTaken(ani_env *env, ani_class cls, ani_object object, double dateTaken);
    static ani_status SetOrientation(ani_env *env, ani_class cls, ani_object object, double orientation);
    static ani_status SetIsFavorite(ani_env *env, ani_class cls, ani_object object, bool isFavorite);
    static ani_status SetTitle(ani_env *env, ani_class cls, ani_object object, const std::string &title);
    static ani_status SetPosition(ani_env *env, ani_class cls, ani_object object, PhotoPositionType position);
    static ani_status SetDateTrashed(ani_env *env, ani_class cls, ani_object object, double dateTrashed);
    static ani_status SetHidden(ani_env *env, ani_class cls, ani_object object, bool hidden);
    static ani_status SetUserComment(ani_env *env, ani_class cls, ani_object object, const std::string &userComment);
    static ani_status SetCameraShotKey(ani_env *env, ani_class cls, ani_object object, const std::string &camera);
    static ani_status SetDateYear(ani_env *env, ani_class cls, ani_object object, const std::string &dateYear);
    static ani_status SetDateMonth(ani_env *env, ani_class cls, ani_object object, const std::string &dateMonth);
    static ani_status SetDateDay(ani_env *env, ani_class cls, ani_object object, const std::string &dateDay);
    static ani_status SetPending(ani_env *env, ani_class cls, ani_object object, bool pending);
    static ani_status SetDateAddedMs(ani_env *env, ani_class cls, ani_object object, double dateAddedMs);
    static ani_status SetDateModifiedMs(ani_env *env, ani_class cls, ani_object object, double dateModifiedMs);
    static ani_status SetDateTrashedMs(ani_env *env, ani_class cls, ani_object object, double dateTrashedMs);
    static ani_status SetSubtype(ani_env *env, ani_class cls, ani_object object, PhotoSubType subtype);
};
} // namespace Media
} // namespace OHOS

#endif // FRAMEWORKS_ANI_SRC_INCLUDE_FILE_ASSET_INFO_ANI_H