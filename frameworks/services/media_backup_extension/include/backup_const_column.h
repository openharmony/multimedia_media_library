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

#ifndef BACKUP_CONST_COLUMN_H
#define BACKUP_CONST_COLUMN_H

#include "backup_const.h"

namespace OHOS {
namespace Media {
// portrait related
enum FaceAnalysisType {
    RECOGNITION = 0,
};
const int32_t IS_LOCAL_TRUE = 1;
const int32_t RENAME_OPERATION_RENAMED = 1;
const std::string CURRENT_ANALYSIS_VERSION = "1.0"; // update-to-date face analysis version
const std::string GALLERY_TABLE_MERGE_FACE = "merge_face";
const std::string GALLERY_TABLE_MERGE_TAG = "merge_tag";
const std::string GALLERY_TAG_ID = "tag_id";
const std::string GALLERY_GROUP_TAG = "merge_tag.group_tag";
const std::string GALLERY_TAG_NAME = "merge_tag.tag_name";
const std::string GALLERY_USER_OPERATION = "merge_tag.user_operation";
const std::string GALLERY_RENAME_OPERATION = "merge_tag.rename_operation";
const std::string GALLERY_SCALE_X = "merge_face.scale_x";
const std::string GALLERY_SCALE_Y = "merge_face.scale_y";
const std::string GALLERY_SCALE_WIDTH = "merge_face.scale_width";
const std::string GALLERY_SCALE_HEIGHT = "merge_face.scale_height";
const std::string GALLERY_PITCH = "merge_face.pitch";
const std::string GALLERY_YAW = "merge_face.yaw";
const std::string GALLERY_ROLL = "merge_face.roll";
const std::string GALLERY_PROB = "merge_face.prob";
const std::string GALLERY_TOTAL_FACE = "merge_face.total_face";
const std::string GALLERY_FACE_ID = "merge_face.face_id";
const std::string GALLERY_LANDMARKS = "merge_face.landmarks";
const std::string GALLERY_MERGE_FACE_HASH = GALLERY_TABLE_MERGE_FACE + "." + GALLERY_HASH;
const std::string GALLERY_MERGE_FACE_TAG_ID = GALLERY_TABLE_MERGE_FACE + "." + GALLERY_TAG_ID;
const std::string GALLERY_MERGE_TAG_TAG_ID = GALLERY_TABLE_MERGE_TAG + "." + GALLERY_TAG_ID;
const std::string E_VERSION = "-1";
const std::string TAG_ID_PREFIX = "ser_";
const std::string TAG_ID_UNPROCESSED = "-1";
const std::string GALLERY_TAG_NAME_NOT_NULL_OR_EMPTY = GALLERY_TAG_NAME + " IS NOT NULL AND " + GALLERY_TAG_NAME +
    " != ''";
const std::string GALLERY_TAG_WITH_PHOTOS = "EXISTS (SELECT 1 FROM " + GALLERY_TABLE_MERGE_FACE + " INNER JOIN \
    gallery_media ON " + GALLERY_MERGE_FACE_HASH + " = gallery_media.hash WHERE " + ALL_PHOTOS_WHERE_CLAUSE + " AND " +
    GALLERY_MERGE_FACE_TAG_ID + " = " + GALLERY_MERGE_TAG_TAG_ID + ")";
const std::string GALLERY_PORTRAIT_ALBUM_TABLE = GALLERY_TABLE_MERGE_TAG + " WHERE " +
    GALLERY_TAG_NAME_NOT_NULL_OR_EMPTY + " AND " + GALLERY_TAG_WITH_PHOTOS;
const std::string QUERY_GALLERY_PORTRAIT_ALBUM_COUNT = "SELECT count(1) as count FROM " + GALLERY_PORTRAIT_ALBUM_TABLE;
const std::string GALLERY_FACE_TABLE_JOIN_TAG = GALLERY_TABLE_MERGE_FACE + " INNER JOIN " + GALLERY_TABLE_MERGE_TAG +
    " ON " + GALLERY_MERGE_FACE_TAG_ID + " = " + GALLERY_MERGE_TAG_TAG_ID;
} // namespace Media
} // namespace OHOS

#endif  // BACKUP_CONST_COLUMN_H