/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#ifndef OHOS_MEDIALIBRARY_COUNT_PICKER_STRATEGY_REGISTER_H
#define OHOS_MEDIALIBRARY_COUNT_PICKER_STRATEGY_REGISTER_H

#include <memory>
#include <string>

#include "album_change_info.h"
#include "photo_asset_change_info.h"
#include "medialibrary_rdbstore.h"
#include "medialibrary_rdb_utils.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "result_set_utils.h"

namespace OHOS {
namespace Media {
namespace AccurateRefresh {

/**
 * 封面挑选器接口（策略对外统一入口）
 */
class ICoverPickerStrategy {
public:
    virtual ~ICoverPickerStrategy() = default;
    virtual bool PickCover(const UpdateAlbumData &baseInfo, AnalysisAlbumRefreshInfo &info) = 0;
};


/**
 * 通用封面挑选基类,适用于普通智慧相册
 */
class CoverPickerStrategyBase : public ICoverPickerStrategy {
public:
    bool PickCover(const UpdateAlbumData &baseInfo, AnalysisAlbumRefreshInfo &info) override;

protected:
    virtual std::string QueryCover(const std::shared_ptr<MediaLibraryRdbStore> &rdb,
        const UpdateAlbumData &baseInfo);
};

} // namespace AccurateRefresh
} // namespace Media
} // namespace OHOS
#endif // OHOS_MEDIALIBRARY_COUNT_PICKER_STRATEGY_REGISTER_H
