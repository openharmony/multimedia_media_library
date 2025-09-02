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

#include "medialibrary_meta_recovery_test_utils.h"

#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <unordered_map>
#include <userfile_manager_types.h>

#include "medialibrary_type_const.h"
#include "media_column.h"

namespace OHOS {
namespace Media {
namespace {
static const std::unordered_map<std::string, ResultSetDataType> RESULT_TYPE_MAP = {
    // 不能填unique字段， file_id, virtual path
    { MediaColumn::MEDIA_FILE_PATH, TYPE_STRING },
    { MediaColumn::MEDIA_SIZE, TYPE_INT64 },
    { MediaColumn::MEDIA_TITLE, TYPE_STRING },
    { MediaColumn::MEDIA_NAME, TYPE_STRING },
    { MediaColumn::MEDIA_TYPE, TYPE_INT32 },
    { MediaColumn::MEDIA_MIME_TYPE, TYPE_STRING },
    { MediaColumn::MEDIA_OWNER_PACKAGE, TYPE_STRING },
    { MediaColumn::MEDIA_OWNER_APPID, TYPE_STRING },
    { MediaColumn::MEDIA_PACKAGE_NAME, TYPE_STRING },
    { MediaColumn::MEDIA_DEVICE_NAME, TYPE_STRING },
    { MediaColumn::MEDIA_DATE_ADDED, TYPE_INT64 },
    { MediaColumn::MEDIA_DATE_MODIFIED, TYPE_INT64 },
    { MediaColumn::MEDIA_DATE_TAKEN, TYPE_INT64 },
    { MediaColumn::MEDIA_DURATION, TYPE_INT32 },
    { MediaColumn::MEDIA_TIME_PENDING, TYPE_INT64 },
    { MediaColumn::MEDIA_IS_FAV, TYPE_INT32 },
    { MediaColumn::MEDIA_DATE_TRASHED, TYPE_INT64 },
    { MediaColumn::MEDIA_DATE_DELETED, TYPE_INT64 },
    { MediaColumn::MEDIA_HIDDEN, TYPE_INT32 },
    { MediaColumn::MEDIA_PARENT_ID, TYPE_INT32 },
    { MediaColumn::MEDIA_RELATIVE_PATH, TYPE_STRING },
    { PhotoColumn::PHOTO_DIRTY, TYPE_INT32 },
    { PhotoColumn::PHOTO_CLOUD_ID, TYPE_STRING },
    { PhotoColumn::PHOTO_META_DATE_MODIFIED, TYPE_INT64 },
    { PhotoColumn::PHOTO_SYNC_STATUS, TYPE_INT32 },
    { PhotoColumn::PHOTO_CLOUD_VERSION, TYPE_INT64 },
    { PhotoColumn::PHOTO_ORIENTATION, TYPE_INT32 },
    { PhotoColumn::PHOTO_LATITUDE, TYPE_DOUBLE },
    { PhotoColumn::PHOTO_LONGITUDE, TYPE_DOUBLE },
    { PhotoColumn::PHOTO_HEIGHT, TYPE_INT32 },
    { PhotoColumn::PHOTO_WIDTH, TYPE_INT32 },
    { PhotoColumn::PHOTO_EDIT_TIME, TYPE_INT64 },
    { PhotoColumn::PHOTO_LCD_VISIT_TIME, TYPE_INT64 },
    { PhotoColumn::PHOTO_POSITION, TYPE_INT32 },
    { PhotoColumn::PHOTO_SUBTYPE, TYPE_INT32 },
    { PhotoColumn::PHOTO_ORIGINAL_SUBTYPE, TYPE_INT32 },
    { PhotoColumn::CAMERA_SHOT_KEY, TYPE_STRING },
    { PhotoColumn::PHOTO_USER_COMMENT, TYPE_STRING },
    { PhotoColumn::PHOTO_ALL_EXIF, TYPE_STRING },
    { PhotoColumn::PHOTO_DATE_YEAR, TYPE_STRING },
    { PhotoColumn::PHOTO_DATE_MONTH, TYPE_STRING },
    { PhotoColumn::PHOTO_DATE_DAY, TYPE_STRING },
    { PhotoColumn::PHOTO_SHOOTING_MODE, TYPE_STRING },
    { PhotoColumn::PHOTO_SHOOTING_MODE_TAG, TYPE_STRING },
    { PhotoColumn::PHOTO_LAST_VISIT_TIME, TYPE_INT64 },
    { PhotoColumn::PHOTO_HIDDEN_TIME, TYPE_INT64 },
    { PhotoColumn::PHOTO_THUMB_STATUS, TYPE_INT32 },
    { PhotoColumn::PHOTO_CLEAN_FLAG, TYPE_INT32 },
    { PhotoColumn::PHOTO_ID, TYPE_STRING },
    { PhotoColumn::PHOTO_QUALITY, TYPE_INT32 },
    { PhotoColumn::PHOTO_FIRST_VISIT_TIME, TYPE_INT64 },
    { PhotoColumn::PHOTO_DEFERRED_PROC_TYPE, TYPE_INT32 },
    { PhotoColumn::PHOTO_DYNAMIC_RANGE_TYPE, TYPE_INT32 },
    { PhotoColumn::MOVING_PHOTO_EFFECT_MODE, TYPE_INT32 },
    { PhotoColumn::PHOTO_COVER_POSITION, TYPE_INT64 },
    { PhotoColumn::PHOTO_LCD_SIZE, TYPE_STRING },
    { PhotoColumn::PHOTO_THUMB_SIZE, TYPE_STRING },
    { PhotoColumn::PHOTO_FRONT_CAMERA, TYPE_STRING },
    { PhotoColumn::PHOTO_IS_TEMP, TYPE_INT32 },
    { PhotoColumn::PHOTO_BURST_COVER_LEVEL, TYPE_INT32 },
    { PhotoColumn::PHOTO_BURST_KEY, TYPE_STRING },
    { PhotoColumn::PHOTO_CE_AVAILABLE, TYPE_INT32 },
    { PhotoColumn::PHOTO_CE_STATUS_CODE, TYPE_INT32 },
    { PhotoColumn::PHOTO_STRONG_ASSOCIATION, TYPE_INT32 },
    { PhotoColumn::PHOTO_ASSOCIATE_FILE_ID, TYPE_INT32 },
    { PhotoColumn::PHOTO_HAS_CLOUD_WATERMARK, TYPE_INT32 },
    { PhotoColumn::PHOTO_COMPOSITE_DISPLAY_STATUS, TYPE_INT32 },
    { PhotoColumn::PHOTO_DETAIL_TIME, TYPE_STRING },
    { PhotoColumn::PHOTO_OWNER_ALBUM_ID, TYPE_INT32 },
    { PhotoColumn::PHOTO_ORIGINAL_ASSET_CLOUD_ID, TYPE_STRING },
    { PhotoColumn::PHOTO_SOURCE_PATH, TYPE_STRING },
};
}

bool CreateFile(const std::string &filePath)
{
    std::filesystem::path parentPath = std::filesystem::path(filePath).parent_path();
    std::error_code ec;
    bool ret = std::filesystem::exists(parentPath, ec);
    if (ec) {
        GTEST_LOG_(ERROR) << "filesystem::exists failed";
        return false;
    }
    if (!ret) {
        ret = std::filesystem::create_directories(parentPath, ec);
        if (ec || !ret) {
            GTEST_LOG_(ERROR) << "filesystem::create_directories failed";
            return false;
        }
    }

    std::ofstream outFile(filePath, std::ios::app);
    if (!outFile.is_open()) {
        GTEST_LOG_(ERROR) << "Open file failed: " << filePath;
        return false;
    }
    outFile.close();
    return true;
}

void InitFileAsset(FileAsset &fileAsset)
{
    std::string defaultStr = "abcd";
    int32_t defaultInt32 = 1;
    int64_t defaultInt64 = 100;
    double defaultDouble = 3.1415926;
    for (const auto &[name, type] : RESULT_TYPE_MAP) {
        if (type == TYPE_STRING) {
            fileAsset.SetMemberValue(name, defaultStr);
        } else if (type == TYPE_INT32) {
            fileAsset.SetMemberValue(name, defaultInt32);
        } else if (type == TYPE_INT64) {
            fileAsset.SetMemberValue(name, defaultInt64);
        } else if (type == TYPE_DOUBLE) {
            fileAsset.SetMemberValue(name, defaultDouble);
        } else {
            GTEST_LOG_(WARNING) << "type error: " << type;
        }
    }
}

bool CompareFileAsset(const FileAsset &fileAsset1, const FileAsset &fileAsset2)
{
    for (const auto &[name, type] : RESULT_TYPE_MAP) {
        if (type == TYPE_STRING) {
            std::string val1 = fileAsset1.GetStrMember(name);
            std::string val2 = fileAsset2.GetStrMember(name);
            if (val1 != val2) {
                GTEST_LOG_(ERROR) << "name: " << name << ", val1: " << val1 << ", val2: " << val2;
                return false;
            }
        } else if (type == TYPE_INT32) {
            int32_t val1 = fileAsset1.GetInt32Member(name);
            int32_t val2 = fileAsset2.GetInt32Member(name);
            if (val1 != val2) {
                GTEST_LOG_(ERROR) << "name: " << name << ", val1: " << val1 << ", val2: " << val2;
                return false;
            }
        } else if (type == TYPE_INT64) {
            int64_t val1 = fileAsset1.GetInt64Member(name);
            int64_t val2 = fileAsset2.GetInt64Member(name);
            if (val1 != val2) {
                GTEST_LOG_(ERROR) << "name: " << name << ", val1: " << val1 << ", val2: " << val2;
                return false;
            }
        } else if (type == TYPE_DOUBLE) {
            double val1 = fileAsset1.GetDoubleMember(name);
            double val2 = fileAsset2.GetDoubleMember(name);
            if (val1 != val2) {
                GTEST_LOG_(ERROR) << "name: " << name << ", val1: " << val1 << ", val2: " << val2;
                return false;
            }
        } else {
            GTEST_LOG_(WARNING) << "type error: " << type;
        }
    }

    return true;
}

void InitPhotoAlbum(std::vector<std::shared_ptr<PhotoAlbum>> &vecPhotoAlbum, const int32_t count)
{
    PhotoAlbumType albumType = PhotoAlbumType::SOURCE;
    PhotoAlbumSubType albumSubType = PhotoAlbumSubType::SOURCE_GENERIC;
    std::string albumName = "xxxxx";
    int64_t dateModified = 987654;
    int32_t containsHidden = 100;
    int32_t order = 1000;
    std::string bundleName = "qqqqqqq";
    std::string localLanguage = "ppppppp";
    int64_t dateAdded = 123456789;
    int32_t isLocal = 1;
    std::string lPath = "/ffffffff";
    int32_t priority = 500;

    for (int32_t i = 0; i < count; ++i) {
        int albumId = i;
        std::shared_ptr<PhotoAlbum> photoAlbum = std::make_shared<PhotoAlbum>();
        photoAlbum->SetAlbumId(albumId);
        photoAlbum->SetPhotoAlbumType(albumType);
        photoAlbum->SetPhotoAlbumSubType(albumSubType);
        photoAlbum->SetAlbumName(albumName);
        photoAlbum->SetDateModified(dateModified);
        photoAlbum->SetContainsHidden(containsHidden);
        photoAlbum->SetOrder(order);
        photoAlbum->SetBundleName(bundleName);
        photoAlbum->SetLocalLanguage(localLanguage);
        photoAlbum->SetDateAdded(dateAdded);
        photoAlbum->SetIsLocal(isLocal);
        photoAlbum->SetLPath(lPath);
        photoAlbum->SetPriority(priority);
        vecPhotoAlbum.emplace_back(photoAlbum);
    }
}

bool ComparePhotoAlbum(const std::vector<std::shared_ptr<PhotoAlbum>> &vecPhotoAlbum1,
    const std::vector<std::shared_ptr<PhotoAlbum>> &vecPhotoAlbum2)
{
    const int32_t n1 = vecPhotoAlbum1.size();
    const int32_t n2 = vecPhotoAlbum2.size();
    if (n1 != n2) {
        return false;
    }

    for (int32_t i = 0; i < n1; ++i) {
        if (vecPhotoAlbum1[i]->GetAlbumId() != vecPhotoAlbum2[i]->GetAlbumId()) {
            return false;
        }
        if (vecPhotoAlbum1[i]->GetPhotoAlbumType()!= vecPhotoAlbum2[i]->GetPhotoAlbumType()) {
            return false;
        }
        if (vecPhotoAlbum1[i]->GetPhotoAlbumSubType()!= vecPhotoAlbum2[i]->GetPhotoAlbumSubType()) {
            return false;
        }
        if (vecPhotoAlbum1[i]->GetAlbumName()!= vecPhotoAlbum2[i]->GetAlbumName()) {
            return false;
        }
        if (vecPhotoAlbum1[i]->GetDateModified()!= vecPhotoAlbum2[i]->GetDateModified()) {
            return false;
        }
        if (vecPhotoAlbum1[i]->GetContainsHidden()!= vecPhotoAlbum2[i]->GetContainsHidden()) {
            return false;
        }
        if (vecPhotoAlbum1[i]->GetOrder()!= vecPhotoAlbum2[i]->GetOrder()) {
            return false;
        }
        if (vecPhotoAlbum1[i]->GetBundleName()!= vecPhotoAlbum2[i]->GetBundleName()) {
            return false;
        }
        if (vecPhotoAlbum1[i]->GetLocalLanguage()!= vecPhotoAlbum2[i]->GetLocalLanguage()) {
            return false;
        }
        if (vecPhotoAlbum1[i]->GetDateAdded()!= vecPhotoAlbum2[i]->GetDateAdded()) {
            return false;
        }
        if (vecPhotoAlbum1[i]->GetIsLocal()!= vecPhotoAlbum2[i]->GetIsLocal()) {
            return false;
        }
        if (vecPhotoAlbum1[i]->GetLPath()!= vecPhotoAlbum2[i]->GetLPath()) {
            return false;
        }
        if (vecPhotoAlbum1[i]->GetPriority()!= vecPhotoAlbum2[i]->GetPriority()) {
            return false;
        }
    }

    return true;
}
}
}