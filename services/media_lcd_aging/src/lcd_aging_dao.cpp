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
#define MLOG_TAG "Lcd_Aging"

#include "lcd_aging_dao.h"

#include "media_log.h"
#include "medialibrary_errno.h"
#include "medialibrary_unistore_manager.h"
#include "result_set_reader.h"

namespace OHOS::Media {

int32_t LcdAgingDao::GetCurrentNumberOfLcd(int64_t &lcdNumber)
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, E_ERR, "GetCurrentNumberOfLcd Failed to get rdbStore.");
    auto resultSet = rdbStore->QuerySql(SQL_GET_TOTAL_NUMBER_OF_LCD);
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr && resultSet->GoToFirstRow() == NativeRdb::E_OK, E_ERR,
        "GetCurrentNumberOfLcd Failed to query number of lcd");
    lcdNumber = GetInt64Val("count", resultSet);
    resultSet->Close();
    return E_OK;
}
}  // namespace OHOS::Media