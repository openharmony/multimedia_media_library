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
#ifndef OHOS_MEDIALIBRARY_DEFAULT_STRATEGIES_REGISTER_H
#define OHOS_MEDIALIBRARY_DEFAULT_STRATEGIES_REGISTER_H

#include <memory>
#include <string>
#include "album_change_info.h"
#include "analysis_strategy_registry.h"
#include "count_strategy.h"
#include "cover_strategy.h"
#include "cover_picker_strategy.h"
#include "effective_strategy.h"
#include "media_file_utils.h"
#include "media_log.h"

namespace OHOS {
namespace Media {
namespace AccurateRefresh {
class DefaultAlbumEffectiveStrategy : public AlbumEffectiveStrategyBase {};

class DefaultCountStrategy : public CountStrategyBase {};

class DefaultCoverStrategy : public CoverStrategyBase {};

class DefaultCoverPickerStrategy : public CoverPickerStrategyBase {};

} // namespace AccurateRefresh
} // namespace Media
} // namespace OHOS
#endif // OHOS_MEDIALIBRARY_DEFAULT_STRATEGIES_REGISTER_H
