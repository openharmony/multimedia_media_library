/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import Extension from '@ohos.application.DataShareExtensionAbility';

export default class DataShareExtAbility extends Extension {
  private rdbStore_;

  onCreate(want): void {
    console.log('[MediaDataShare] <<Provider>> DataShareExtAbility onCreate, want:' + want.abilityName);
  }

  getFileTypes(uri: string, mimeTypeFilter: string): void {
    console.info('[MediaDataShare] <<Provider>> [getFileTypes] enter');
  }

  insert(uri, value, callback): void {
    console.info('[MediaDataShare] <<Provider>> [insert] enter');
  }

  update(uri, value, predicates, callback): void {
    console.info('[MediaDataShare] <<Provider>> [update] enter');
  }

  delete(uri, predicates, callback): void {
    console.info('[MediaDataShare] <<Provider>> [delete] enter');
  }

  query(uri, columns, predicates, callback): void {
    console.info('[MediaDataShare] <<Provider>> [query] enter');
  }

  getType(uri: string): void {
    console.info('[MediaDataShare] <<Provider>> [getType] enter');
  }

  batchInsert(uri: string, valueBuckets, callback): void {
    console.info('[MediaDataShare] <<Provider>> [batchInsert] enter');
  }

  normalizeUri(uri: string): void {
    console.info('[MediaDataShare] <<Provider>> [normalizeUri] enter');
  }

  denormalizeUri(uri: string): void {
    console.info('[MediaDataShare] <<Provider>> [denormalizeUri] enter');
  }
};
