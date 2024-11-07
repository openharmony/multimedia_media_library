/*
 * Copyright (C) 2024-2024 Huawei Device Co., Ltd.
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

#ifndef FRAMEWORKS_SERVICES_MEDIA_MULTI_STAGES_CAPTURE_INCLUDE_STORY_DB_SQLS_H
#define FRAMEWORKS_SERVICES_MEDIA_MULTI_STAGES_CAPTURE_INCLUDE_STORY_DB_SQLS_H

#include "story_album_column.h"
#include "story_cover_info_column.h"
#include "story_play_info_column.h"
#include "user_photography_info_column.h"
#include "vision_album_column.h"

namespace OHOS {
namespace Media {
const std::string CREATE_HIGHLIGHT_ALBUM_TABLE =
    "CREATE TABLE IF NOT EXISTS " + HIGHLIGHT_ALBUM_TABLE + " ( " +
    ID + " INTEGER PRIMARY KEY AUTOINCREMENT, " +
    ALBUM_ID + " INTEGER, " +
    AI_ALBUM_ID + " INTEGER, " +
    SUB_TITLE + " TEXT, " +
    CLUSTER_TYPE + " TEXT NOT NULL, " +
    CLUSTER_SUB_TYPE + " TEXT NOT NULL, " +
    CLUSTER_CONDITION + " TEXT NOT NULL, " +
    MIN_DATE_ADDED + " BIGINT, " +
    MAX_DATE_ADDED + " BIGINT, " +
    GENERATE_TIME + " BIGINT DEFAULT 0, " +
    HIGHLIGHT_VERSION + " INT NOT NULL, " +
    REMARKS + " TEXT, " +
    HIGHLIGHT_STATUS + " INT, " +
    HIGHLIGHT_INSERT_PIC_COUNT + " INT DEFAULT 0, " +
    HIGHLIGHT_REMOVE_PIC_COUNT + " INT DEFAULT 0, " +
    HIGHLIGHT_SHARE_SCREENSHOT_COUNT + " INT DEFAULT 0, " +
    HIGHLIGHT_SHARE_COVER_COUNT + " INT DEFAULT 0, " +
    HIGHLIGHT_RENAME_COUNT + " INT DEFAULT 0, " +
    HIGHLIGHT_CHANGE_COVER_COUNT + " INT DEFAULT 0, " +
    HIGHLIGHT_RENDER_VIEWED_TIMES + " INT DEFAULT 0, " +
    HIGHLIGHT_RENDER_VIEWED_DURATION + " BIGINT DEFAULT 0, " +
    HIGHLIGHT_ART_LAYOUT_VIEWED_TIMES + " INT DEFAULT 0, " +
    HIGHLIGHT_ART_LAYOUT_VIEWED_DURATION + " BIGINT DEFAULT 0, " +
    HIGHLIGHT_MUSIC_EDIT_COUNT + " INT DEFAULT 0, " +
    HIGHLIGHT_FILTER_EDIT_COUNT + " INT DEFAULT 0, " +
    HIGHLIGHT_IS_MUTED + " BOOL, " +
    HIGHLIGHT_IS_FAVORITE + " BOOL, " +
    HIGHLIGHT_THEME + " TEXT, " +
    HIGHLIGHT_VIDEO_COUNT_CAN_PACK + " INT)";

const std::string CREATE_HIGHLIGHT_COVER_INFO_TABLE =
    "CREATE TABLE IF NOT EXISTS " + HIGHLIGHT_COVER_INFO_TABLE + " ( " +
    ALBUM_ID + " INTEGER, " +
    RATIO + " TEXT, " +
    BACKGROUND + " TEXT, " +
    FOREGROUND + " TEXT, " +
    WORDART + " TEXT, " +
    IS_COVERED + " BOOL, " +
    COLOR + " TEXT, " +
    RADIUS + " INT, " +
    SATURATION + " REAL, " +
    BRIGHTNESS + " REAL, " +
    BACKGROUND_COLOR_TYPE + " INT, " +
    SHADOW_LEVEL + " INT, " +
    TITLE_SCALE_X + " REAL, " +
    TITLE_SCALE_Y + " REAL, " +
    TITLE_RECT_WIDTH + " REAL, " +
    TITLE_RECT_HEIGHT + " REAL, " +
    BACKGROUND_SCALE_X + " REAL, " +
    BACKGROUND_SCALE_Y + " REAL, " +
    BACKGROUND_RECT_WIDTH + " REAL, " +
    BACKGROUND_RECT_HEIGHT + " REAL, " +
    LAYOUT_INDEX + " INT, " +
    COVER_ALGO_VERSION + " INT, " +
    COVER_SERVICE_VERSION + " INT DEFAULT 0, " +
    COVER_KEY + " TEXT, " +
    "PRIMARY KEY (" + ALBUM_ID + "," + RATIO + ")) ";

const std::string CREATE_HIGHLIGHT_PLAY_INFO_TABLE =
    "CREATE TABLE IF NOT EXISTS " + HIGHLIGHT_PLAY_INFO_TABLE + " ( " +
    ALBUM_ID + " INTEGER, " +
    PLAY_INFO_ID + " INTEGER, " +
    MUSIC + " TEXT, " +
    FILTER + " INT, " +
    HIGHLIGHT_PLAY_INFO + " TEXT, " +
    IS_CHOSEN + " BOOL, " +
    PLAY_INFO_VERSION + " INT, " +
    PLAY_SERVICE_VERSION + " INT DEFAULT 0, " +
    HIGHLIGHTING_ALGO_VERSION + " TEXT, " +
    CAMERA_MOVEMENT_ALGO_VERSION + " TEXT, " +
    TRANSITION_ALGO_VERSION + " TEXT, " +
    "PRIMARY KEY (" + ALBUM_ID + "," + PLAY_INFO_ID + ")) ";

const std::string CREATE_USER_PHOTOGRAPHY_INFO_TABLE =
    "CREATE TABLE IF NOT EXISTS " + USER_PHOTOGRAPHY_INFO_TABLE + " ( " +
    AVERAGE_AESTHETICS_SCORE + " INT, " +
    CAPTURE_AESTHETICS_SCORE + " INT, " +
    AVERAGE_AESTHETICS_COUNT + " INT, " +
    CAPTURE_AESTHETICS_COUNT + " INT, " +
    CALCULATE_TIME_START + " BIGINT, " +
    CALCULATE_TIME_END + " BIGINT) ";

const std::string CREATE_ANALYSIS_ALBUM_ASET_MAP_TABLE =
    "CREATE TABLE IF NOT EXISTS " + ANALYSIS_ALBUM_ASSET_MAP_TABLE + " ( " +
    HIGHLIGHT_MAP_ALBUM + " INT, " +
    HIGHLIGHT_MAP_ASSET + " INT, " +
    "PRIMARY KEY (" + HIGHLIGHT_MAP_ALBUM + "," + HIGHLIGHT_MAP_ASSET + ")) ";
 
const std::string CREATE_ANALYSIS_ASSET_SD_MAP_TABLE =
    "CREATE TABLE IF NOT EXISTS " + ANALYSIS_ASSET_SD_MAP_TABLE + " ( " +
    MAP_ASSET_SOURCE + " INT, " +
    MAP_ASSET_DESTINATION + " INT, " +
    "PRIMARY KEY (" + MAP_ASSET_SOURCE + "," + MAP_ASSET_DESTINATION + ")) ";
} // namespace Media
} // namespace OHOS
#endif  // FRAMEWORKS_SERVICES_MEDIA_MULTI_STAGES_CAPTURE_INCLUDE_STORY_DB_SQLS_H