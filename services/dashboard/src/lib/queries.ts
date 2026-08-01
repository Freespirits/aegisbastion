// GraphQL documents against the data-platform Query API contract
// (services/data-platform/internal/queryapi/schema.graphqls, doc 09 §5).

export const ASSETS_QUERY = /* GraphQL */ `
  query Assets($filter: AssetFilter, $first: Int, $after: String) {
    assets(filter: $filter, first: $first, after: $after) {
      nodes {
        uid type value attributes confidence status firstSeen lastSeen roeId
      }
      pageInfo { hasNextPage endCursor totalCount }
    }
  }
`;

export const ASSET_NEIGHBORHOOD_QUERY = /* GraphQL */ `
  query AssetNeighborhood($uid: ID!, $depth: Int) {
    assetNeighborhood(uid: $uid, depth: $depth) {
      root { uid type value status }
      assets { uid type value attributes confidence status firstSeen lastSeen roeId }
      edges { edgeId src dst rel firstSeen lastSeen }
    }
  }
`;

export const FINDINGS_QUERY = /* GraphQL */ `
  query Findings($filter: FindingFilter, $first: Int, $after: String) {
    findings(filter: $filter, first: $first, after: $after) {
      nodes {
        findingId assetUid module checkId title severity state
        validation risk evidenceRef occurrence firstSeen lastSeen taskId
        sensitive createdAt updatedAt
        transitions { fromState toState actor note ts }
      }
      pageInfo { hasNextPage endCursor totalCount }
    }
  }
`;

export const FINDING_QUERY = /* GraphQL */ `
  query Finding($id: ID!) {
    finding(id: $id) {
      findingId assetUid module checkId title severity state
      validation risk evidenceRef occurrence firstSeen lastSeen taskId
      sensitive createdAt updatedAt
      transitions { fromState toState actor note ts }
    }
  }
`;
