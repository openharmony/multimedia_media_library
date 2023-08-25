import TestRunner from '@ohos.application.testRunner';
import AbilityDelegatorRegistry from '@ohos.application.abilityDelegatorRegistry';

let abilityDelegator = undefined;
let abilityDelegatorArguments = undefined;

function translateParamsToString(parameters): string {
  const keySet = new Set([
    '-s class', '-s notClass', '-s suite', '-s it',
    '-s level', '-s testType', '-s size', '-s timeout'
  ])
  let targetParams = '';
  for (const key in parameters) {
    if (keySet.has(key)) {
      targetParams = `${targetParams} ${key} ${parameters[key]}`;
    }
  }
  return targetParams.trim();
}

async function onAbilityCreateCallback(): Promise<void> {
  console.log('onAbilityCreateCallback');
}

async function addAbilityMonitorCallback(err): Promise<void> {
  console.info('addAbilityMonitorCallback : ' + JSON.stringify(err));
}

export default class OpenHarmonyTestRunner implements TestRunner {
  constructor() {
  }

  onPrepare(): void {
    console.info('OpenHarmonyTestRunner OnPrepare ');
  }

  async onRun(): Promise<void> {
    console.log('OpenHarmonyTestRunner onRun run');
    abilityDelegatorArguments = AbilityDelegatorRegistry.getArguments();
    abilityDelegator = AbilityDelegatorRegistry.getAbilityDelegator();
    let testAbilityName = abilityDelegatorArguments.bundleName + '.TestAbility';
    let lMonitor = {
      abilityName: testAbilityName,
      onAbilityCreate: onAbilityCreateCallback,
    };
    abilityDelegator.addAbilityMonitor(lMonitor, addAbilityMonitorCallback);
    let cmd = 'aa start -d 0 -a TestAbility' + ' -b ' + abilityDelegatorArguments.bundleName;
    cmd += ' ' + translateParamsToString(abilityDelegatorArguments.parameters);
    console.info('cmd : ' + cmd);
    abilityDelegator.executeShellCommand(cmd,
      (err, d) => {
        console.info('executeShellCommand : err : ' + JSON.stringify(err));
        console.info('executeShellCommand : data : ' + d.stdResult);
        console.info('executeShellCommand : data : ' + d.exitCode);
      });
    console.info('OpenHarmonyTestRunner onRun end');
  }
};