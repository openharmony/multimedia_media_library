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

#ifndef CLOUD_ENHANCEMENT_URI_H_
#define CLOUD_ENHANCEMENT_URI_H_
#include "base_data_uri.h"

namespace OHOS {
namespace Media {
const std::string OPRN_ENHANCEMENT_ADD = "add_enhancement";
const std::string OPRN_ENHANCEMENT_PRIORITIZE = "prioritize_enhancement";
const std::string OPRN_ENHANCEMENT_CANCEL = "cancel_enhancement";
const std::string OPRN_ENHANCEMENT_CANCEL_ALL = "cancel_all_enhancement";
const std::string OPRN_ENHANCEMENT_SYNC = "sync_all_enhancement";
const std::string OPRN_ENHANCEMENT_QUERY = "query_enhancement";
const std::string OPRN_ENHANCEMENT_GET_PAIR = "get_pair_enhancement";
const std::string PAH_CLOUD_ENHANCEMENT_OPERATE = "cloud_enhancement_operation";

const std::string PAH_CLOUD_ENHANCEMENT_ADD = MEDIALIBRARY_DATA_URI + "/" + PAH_CLOUD_ENHANCEMENT_OPERATE + "/" +
    OPRN_ENHANCEMENT_ADD;
const std::string PAH_CLOUD_ENHANCEMENT_PRIORITIZE = MEDIALIBRARY_DATA_URI + "/" + PAH_CLOUD_ENHANCEMENT_OPERATE + "/" +
    OPRN_ENHANCEMENT_PRIORITIZE;
const std::string PAH_CLOUD_ENHANCEMENT_CANCEL = MEDIALIBRARY_DATA_URI + "/" + PAH_CLOUD_ENHANCEMENT_OPERATE + "/" +
    OPRN_ENHANCEMENT_CANCEL;
const std::string PAH_CLOUD_ENHANCEMENT_CANCEL_ALL = MEDIALIBRARY_DATA_URI + "/" + PAH_CLOUD_ENHANCEMENT_OPERATE + "/" +
    OPRN_ENHANCEMENT_CANCEL_ALL;
const std::string PAH_CLOUD_ENHANCEMENT_SYNC = MEDIALIBRARY_DATA_URI + "/" + PAH_CLOUD_ENHANCEMENT_OPERATE + "/" +
    OPRN_ENHANCEMENT_SYNC;
const std::string PAH_CLOUD_ENHANCEMENT_QUERY = MEDIALIBRARY_DATA_URI + "/" + PAH_CLOUD_ENHANCEMENT_OPERATE + "/" +
    OPRN_ENHANCEMENT_QUERY;
const std::string PAH_CLOUD_ENHANCEMENT_GET_PAIR = MEDIALIBRARY_DATA_URI + "/" + PAH_CLOUD_ENHANCEMENT_OPERATE + "/" +
    OPRN_ENHANCEMENT_GET_PAIR;

} // namespace Media
} // namespace OHOS

#endif // CLOUD_ENHANCEMENT_URI_H_