/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#ifndef OHOS_MEDIA_LCD_AGING_DAO_H
#define OHOS_MEDIA_LCD_AGING_DAO_H

#include <string>
#include <vector>

#include "lcd_aging_file_info.h"
#include "photos_po.h"

namespace OHOS::Media {
using namespace OHOS::Media::ORM;

class LcdAgingDao {
public:
    int32_t GetCurrentNumberOfLcd(int64_t &lcdNumber);
    int32_t QueryAgingLcdDataTrashed(const int32_t size, const std::vector<std::string> &notAgingFileIds,
        std::vector<PhotosPo> &lcdAgingPoList);
    int32_t QueryAgingLcdDataNotTrashed(const int32_t size, const std::vector<std::string> &notAgingFileIds,
        std::vector<PhotosPo> &lcdAgingPoList);
    int32_t SetLcdNotDownloadStatus(const std::vector<std::string> &fileIds);
    int32_t RevertToLcdDownloadStatus(const std::vector<std::string> &fileIds);
    int32_t UpdateLcdFileSize(const std::vector<LcdAgingFileInfo> &agingFileInfos);

private:
    int32_t QueryAgingLcdDataInternal(const int32_t size, const std::vector<std::string> &notAgingFileIds,
        std::vector<PhotosPo> &lcdAgingPoList, const std::string &sql, const char *logPrefix);

private:
    // 查询本地LCD数量: 1、图片在本地(position = 1 OR 3)    2、纯云图(position = 2)且LCD已下载(thumb_status为0或2)
    const std::string SQL_GET_TOTAL_NUMBER_OF_LCD = "\
        SELECT count(1) AS count \
        FROM Photos \
        WHERE \
            ((position = 1 OR position = 3) OR \
            (position = 2 AND (thumb_status & 1) = 0)) AND \
            clean_flag = 0;";
    // 查询可以老化的图片: 纯云图、非收藏，需要排除以下图片: 相册封面(AlbumCoverFileId)、拍摄模式封面(ShootingCoverFileId)、
    // 其他原因不可老化的图片(NotAgingFileId)、最近拍摄的图片(LatestFileId)
    const std::string SQL_QUERY_NOT_AGING_DATA = "\
        WITH AlbumCoverFileId AS ( \
            SELECT DISTINCT CAST(SUBSTR(cover_uri, 20, INSTR(SUBSTR(cover_uri, 20), '/') - 1) AS INTEGER) AS file_id \
            FROM PhotoAlbum \
            WHERE cover_uri IS NOT NULL AND cover_uri <> '' \
        ), \
        ShootingCoverFileId AS ( \
            SELECT DISTINCT CAST(SUBSTR(cover_uri, 20, INSTR(SUBSTR(cover_uri, 20), '/') - 1) AS INTEGER) AS file_id \
            FROM AnalysisAlbum \
            WHERE album_subtype = 4101 \
                AND cover_uri IS NOT NULL AND cover_uri <> '' \
        ), \
        NotAgingFileId AS ( \
            SELECT DISTINCT file_id \
            FROM Photos \
            WHERE file_id in ({0}) \
        ), \
        LatestFileId AS ( \
            SELECT DISTINCT file_id \
            FROM Photos \
            WHERE sync_status = 0 \
            AND clean_flag = 0 \
            AND time_pending = 0 \
            AND is_temp = 0 \
            ORDER BY date_taken DESC \
            LIMIT 4000 \
        ), \
        ExcludeFileId AS ( \
            SELECT file_id FROM AlbumCoverFileId \
            UNION \
            SELECT file_id FROM NotAgingFileId \
            UNION \
            SELECT file_id FROM LatestFileId \
            UNION \
            SELECT file_id FROM ShootingCoverFileId \
        ) \
        SELECT P.* \
        FROM Photos P \
        INNER JOIN tab_photos_ext E \
            ON E.photo_id = P.file_id AND E.lcd_file_modify_time < ? AND E.lcd_using_status = 0 \
        WHERE P.sync_status = 0 \
            AND P.clean_flag = 0 \
            AND P.time_pending = 0 \
            AND P.is_temp = 0 \
            AND P.position = 2 \
            AND P.is_favorite = 0 \
            AND (P.thumb_status & 1) = 0 \
            AND NOT EXISTS (SELECT 1 FROM ExcludeFileId WHERE file_id = P.file_id) ";
    // 回收站的图片
    const std::string SQL_QUERY_AGING_LCD_DATA_TRASHED = SQL_QUERY_NOT_AGING_DATA + "\
            AND P.date_trashed > 0 \
        LIMIT ?;";
    // 非回收站的图片，按照LCD访问时间、编辑时间、拍摄时间排序
    const std::string SQL_QUERY_AGING_LCD_DATA_NOT_TRASHED = SQL_QUERY_NOT_AGING_DATA + "\
            AND P.date_trashed = 0 \
        ORDER BY P.real_lcd_visit_time ASC, P.edit_time ASC, P.date_taken ASC \
        LIMIT ?;";
    const std::string SQL_UPDATE_THUMB_STATUS = "\
        UPDATE Photos \
            SET thumb_status = thumb_status | ? \
        WHERE file_id IN ({0});";
    const std::string SQL_REVERT_THUMB_STATUS = "\
        UPDATE Photos \
            SET thumb_status = thumb_status & ? \
        WHERE file_id IN ({0});";
};
}  // namespace OHOS::Media
#endif  // OHOS_MEDIA_LCD_AGING_DAO_H