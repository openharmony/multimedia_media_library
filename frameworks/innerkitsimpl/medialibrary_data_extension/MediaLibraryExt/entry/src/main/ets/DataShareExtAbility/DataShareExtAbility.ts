/*
 * Copyright (C) 2021-2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License"),
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

import Extension from '@ohos.application.DataShareExtensionAbility'

export default class DataShareExtAbility extends Extension {
    private rdbStore_;

    onCreate(want) {
        console.log('[ttt] [MediaDataShare] <<Provider>> DataShareExtAbility onCreate, want:' + want.abilityName);
    }

    getFileTypes(uri: string, mimeTypeFilter: string) {
        console.info('[ttt] [MediaDataShare] <<Provider>> [getFileTypes] enter');
    }

    insert(uri, value, callback) {
        console.info('[ttt] [MediaDataShare] <<Provider>> [insert] enter');
    }

    update(uri, value, predicates, callback) {
        console.info('[ttt] [MediaDataShare] <<Provider>> [update] enter');
    }

    delete(uri, predicates, callback) {
        console.info('[ttt] [MediaDataShare] <<Provider>> [delete] enter');
    }

    query(uri, columns, predicates, callback) {
        console.info('[ttt] [MediaDataShare] <<Provider>> [query] enter');
    }

    getType(uri: string) {
        console.info('[ttt] [MediaDataShare] <<Provider>> [getType] enter');
    }

    batchInsert(uri: string, valueBuckets, callback) {
        console.info('[ttt] [MediaDataShare] <<Provider>> [batchInsert] enter');
    }

    normalizeUri(uri: string) {
        console.info('[ttt] [MediaDataShare] <<Provider>> [normalizeUri] enter');
    }

    denormalizeUri(uri: string) {
        console.info('[ttt] [MediaDataShare] <<Provider>> [denormalizeUri] enter');
    }
};
