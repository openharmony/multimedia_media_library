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
    ALBUM_ID + " INTEGER PRIMARY KEY, " +
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
    HIGHLIGHT_ART_LAYOUT_VIEWED_DURATION + " BIGINT DEFAULT 0) ";

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
    TITLE_SCALE_X + " REAL, " +
    TITLE_SCALE_Y + " REAL, " +
    TITLE_RECT_WIDTH + " REAL, " +
    TITLE_RECT_HEIGHT + " REAL, " +
    BACKGROUND_SCALE_X + " REAL, " +
    BACKGROUND_SCALE_Y + " REAL, " +
    BACKGROUND_RECT_WIDTH + " REAL, " +
    BACKGROUND_RECT_HEIGHT + " REAL, " +
    COVER_ALGO_VERSION + " INT, " +
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
    "PRIMARY KEY (" + ALBUM_ID + "," + PLAY_INFO_ID + ")) ";

const std::string CREATE_USER_PHOTOGRAPHY_INFO_TABLE =
    "CREATE TABLE IF NOT EXISTS " + USER_PHOTOGRAPHY_INFO_TABLE + " ( " +
    AVERAGE_AESTHETICS_SCORE + " INT, " +
    CAPTURE_AESTHETICS_SCORE + " INT, " +
    AVERAGE_AESTHETICS_COUNT + " INT, " +
    CAPTURE_AESTHETICS_COUNT + " INT, " +
    CALCULATE_TIME_START + " BIGINT, " +
    CALCULATE_TIME_END + " BIGINT) ";
} // namespace Media
} // namespace OHOS
#endif  // FRAMEWORKS_SERVICES_MEDIA_MULTI_STAGES_CAPTURE_INCLUDE_STORY_DB_SQLS_H