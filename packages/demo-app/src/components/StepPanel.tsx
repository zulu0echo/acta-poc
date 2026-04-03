import { useSimulation } from '../simulation/SimulationEngine'
import Step1Actors from './steps/Step1Actors'
import Step2Schema from './steps/Step2Schema'
import Step3Issuance from './steps/Step3Issuance'
import Step4Anchor from './steps/Step4Anchor'
import Step5Predicate from './steps/Step5Predicate'
import Step6Policy from './steps/Step6Policy'
import Step7Request from './steps/Step7Request'
import Step8Proof from './steps/Step8Proof'
import Step9Verify from './steps/Step9Verify'
import Step10Access from './steps/Step10Access'

const STEP_COMPONENTS: Record<number, () => JSX.Element> = {
  1:  Step1Actors,
  2:  Step2Schema,
  3:  Step3Issuance,
  4:  Step4Anchor,
  5:  Step5Predicate,
  6:  Step6Policy,
  7:  Step7Request,
  8:  Step8Proof,
  9:  Step9Verify,
  10: Step10Access,
}

export default function StepPanel() {
  const { state } = useSimulation()
  const Component = STEP_COMPONENTS[state.currentStep]

  return (
    <div className="p-6 h-full">
      <Component />
    </div>
  )
}
