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

#ifndef CLONE_SOURCE_H
#define CLONE_SOURCE_H

#include <string>

#include "location_db_sqls.h"
#include "result_set_utils.h"
#include "rdb_helper.h"
#include "backup_const_column.h"

namespace OHOS {
namespace Media {
enum class InsertType {
    PHOTOS = 0,
    PHOTO_ALBUM,
    PHOTO_MAP,
    ANALYSIS_ALBUM,
    FACE_TAG_TBL,
    IMG_FACE_TBL,
    ANALYSIS_PHOTO_MAP,
    AUDIOS,
    ANALYSIS_GEO_DICTIONARY,
    TAB_ANALYSIS_LABEL,
    TAB_ANALYSIS_VIDEO_LABEL,
};

const std::string CREATE_FACE_TAG_TBL_FOR_ONCREATE = "CREATE TABLE IF NOT EXISTS " + VISION_FACE_TAG_TABLE + " (" +
    FACE_TAG_COL_ID + " INTEGER PRIMARY KEY AUTOINCREMENT, " +
    FACE_TAG_COL_TAG_ID + " TEXT, " +
    FACE_TAG_COL_TAG_NAME + " TEXT, " +
    FACE_TAG_COL_USER_OPERATION + " INT, " +
    FACE_TAG_COL_GROUP_TAG + " TEXT, " +
    FACE_TAG_COL_RENAME_OPERATION + " INT, " +
    FACE_TAG_COL_CENTER_FEATURES + " BLOB, " +
    FACE_TAG_COL_TAG_VERSION + " TEXT, " +
    FACE_TAG_COL_USER_DISPLAY_LEVEL + " INT, " +
    FACE_TAG_COL_TAG_ORDER + " INT, " +
    FACE_TAG_COL_IS_ME + " INT, " +
    FACE_TAG_COL_COVER_URI + " TEXT, " +
    FACE_TAG_COL_COUNT + " INT, " +
    FACE_TAG_COL_DATE_MODIFY + " BIGINT, " +
    FACE_TAG_COL_ALBUM_TYPE + " INT, " +
    FACE_TAG_COL_IS_REMOVED + " INT, " +
    FACE_TAG_COL_ANALYSIS_VERSION + " TEXT)";
const std::string CREATE_IMG_FACE_TBL_FOR_ONCREATE = "CREATE TABLE IF NOT EXISTS " + VISION_IMAGE_FACE_TABLE + " (" +
    IMAGE_FACE_COL_ID + " INTEGER PRIMARY KEY AUTOINCREMENT, " +
    IMAGE_FACE_COL_FILE_ID + " INT, " +
    IMAGE_FACE_COL_FACE_ID + " TEXT, " +
    IMAGE_FACE_COL_TAG_ID + " TEXT, " +
    IMAGE_FACE_COL_SCALE_X + " REAL, " +
    IMAGE_FACE_COL_SCALE_Y + " REAL, " +
    IMAGE_FACE_COL_SCALE_WIDTH + " REAL, " +
    IMAGE_FACE_COL_SCALE_HEIGHT + " REAL, " +
    IMAGE_FACE_COL_LANDMARKS + " BLOB, " +
    IMAGE_FACE_COL_PITCH + " REAL, " +
    IMAGE_FACE_COL_YAW + " REAL, " +
    IMAGE_FACE_COL_ROLL + " REAL, " +
    IMAGE_FACE_COL_PROB + " REAL, " +
    IMAGE_FACE_COL_TOTAL_FACES + " INT, " +
    IMAGE_FACE_COL_FACE_VERSION + " TEXT, " +
    IMAGE_FACE_COL_FEATURES_VERSION + " TEXT, " +
    IMAGE_FACE_COL_FEATURES + " BLOB, " +
    IMAGE_FACE_COL_FACE_OCCLUSION + " INT, " +
    IMAGE_FACE_COL_ANALYSIS_VERSION + " TEXT, " +
    IMAGE_FACE_COL_BEAUTY_BOUNDER_X + " REAL, " +
    IMAGE_FACE_COL_BEAUTY_BOUNDER_Y + " REAL, " +
    IMAGE_FACE_COL_BEAUTY_BOUNDER_WIDTH + " REAL, " +
    IMAGE_FACE_COL_BEAUTY_BOUNDER_HEIGHT + " REAL, " +
    IMAGE_FACE_COL_AESTHETICS_SCORE + " REAL, " +
    IMAGE_FACE_COL_BEAUTY_BOUNDER_VERSION + " TEXT, " +
    IMAGE_FACE_COL_IS_EXCLUDED + " INT)";

class CloneOpenCall;

class CloneSource {
public:
    void Init(const std::string &path, const std::vector<std::string> &tableList);
    void Insert(const std::vector<std::string> &tableList);
    void InsertByType(InsertType insertType);
    void InsertPhoto();
    void InsertPhotoAlbum();
    void InsertPhotoMap();
    void InsertAnalysisAlbum();
    void InsertAnalysisPhotoMap();
    void InsertAudio();
    void InsertFaceTag();
    void InsertImgFaceTbl();
    void InsertAnalysisGeoDictionary();
    void InsertTabAnalysisLabel();
    void InsertTabAnalysisVideoLabel();
    std::shared_ptr<NativeRdb::RdbStore> cloneStorePtr_;
};

class CloneOpenCall : public NativeRdb::RdbOpenCallback {
public:
    int32_t OnCreate(NativeRdb::RdbStore &rdbStore) override;
    int32_t OnUpgrade(NativeRdb::RdbStore &rdbStore, int oldVersion, int newVersion) override;
    void Init(const std::vector<std::string> &tableList);
    std::vector<std::string> createSqls_;
};
} // namespace Media
} // namespace OHOS
#endif // CLONE_SOURCE_H