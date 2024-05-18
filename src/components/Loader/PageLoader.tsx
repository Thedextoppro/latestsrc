import styled from 'styled-components'
import Page from '../Layout/Page'
import Spinner from '../../views/Swap/Spinner'

const Wrapper = styled(Page)`
  display: flex;
  justify-content: center;
  align-items: center;
`

const PageLoader: React.FC<React.PropsWithChildren<unknown>> = () => {
  return (
    <Wrapper>
      <Spinner />
    </Wrapper>
  )
}

export default PageLoader
